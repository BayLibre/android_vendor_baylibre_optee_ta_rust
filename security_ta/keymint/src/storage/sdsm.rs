//
// Copyright (C) 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Module that implements the [`SecureDeletionSecretManager`] trait.
//! Based on the Trusty implementation (app/keymint/secure_deletion_secret_manager.rs).

use crate::error::Error;
use core::{cell::RefCell, cmp, ops::DerefMut};
use kmr_common::{
    crypto, keyblob,
    keyblob::{SecureDeletionData, SecureDeletionSlot, SlotPurpose},
    km_err,
};
use log::{debug, error, info, warn};
use optee_utee::{DataFlag, ObjectStorageConstants, PersistentObject, Whence, GenericObject};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Maximum number of attempts to perform a secure storage transaction to read or
// delete a secure deletion secret.
const MAX_TRIES: usize = 3;

// Each secret is 16 bytes.
const SECRET_SIZE: usize = 16;
// The factory reset secret is composed of two secrets and it is stored at offset 0.
// After this position, all the secrets are stored one after the other.
// On each secret a single bit on the first byte is
// set to indicate that the secret is valid (mask 0x80).
const FACTORY_RESET_SECRET_SIZE: usize = SECRET_SIZE * 2;
const FACTORY_RESET_SECRET_POS: usize = 0;
const FACTORY_FIRST_SECURE_DELETION_SECRET_POS: usize =
    FACTORY_RESET_SECRET_POS + FACTORY_RESET_SECRET_SIZE;

// We read secrets in blocks of 32, so 512 bytes.
const BLOCK_SIZE: usize = SECRET_SIZE * 32;

// Limit file size to 16 KiB
const MAX_SECRET_FILE_SIZE: usize = BLOCK_SIZE * 32;

// This is a higher file size limit, with the space above MAX_SECRET_FILE_SIZE
// This is to avoid that keys are degraded as a result of upgrading.
const MAX_SECRET_FILE_SIZE_FOR_UPGRADES: usize = MAX_SECRET_FILE_SIZE + 8 * BLOCK_SIZE;

// Indicate that the slot is in use. This reduces the maximum entropy of each slot
const IN_USE_FLAG: u8 = 0x80;

// Name of the file to store secrets.
const SECURE_DELETION_SECRET_FILENAME: &'static str = "SecureDeletionSecrets_1";

const _: () = assert!(
    BLOCK_SIZE >= FACTORY_RESET_SECRET_SIZE,
    "BLOCK_SIZE should be bigger than FACTORY_RESET_SECRET_SIZE"
);
const _: () = assert!((BLOCK_SIZE % SECRET_SIZE) == 0, "Broke find_empty_slot assumption");
const _: () =
    assert!((FACTORY_RESET_SECRET_SIZE % SECRET_SIZE) == 0, "Broke find_empty_slot assumption");

fn delete_secure_deletion_secret_file() -> Result<(), kmr_common::Error> {
    match PersistentObject::open(
        ObjectStorageConstants::PrivateRee,
        SECURE_DELETION_SECRET_FILENAME.as_bytes(),
        DataFlag::ACCESS_WRITE_META,
    ) {
        Ok(object) => object.close_and_delete().map_err(Error::kmerr),
        Err(e) => match e.kind() {
            optee_utee::ErrorKind::ItemNotFound => Ok(()),
            _ => Err(Error::kmerr(e)),
        },
    }
}

enum RetrieveSecureDeletionSecretFileData {
    EmptyFileFound(SecureDeletionSecretFile),
    CachedDataFound(SecureDeletionData),
    DataFoundOnFile(SecureDeletionData),
}

struct SecureDeletionSecretFile {
    object: PersistentObject,
}

impl SecureDeletionSecretFile {
    // Creating with initial data, possibly over an existing file, is atomic:
    // a crash leaves either no file, the old one or the new one.
    fn create(initial_data: &[u8]) -> Result<SecureDeletionSecretFile, kmr_common::Error> {
        let object = PersistentObject::create(
            ObjectStorageConstants::PrivateRee,
            SECURE_DELETION_SECRET_FILENAME.as_bytes(),
            DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE | DataFlag::OVERWRITE,
            None,
            initial_data,
        )
        .map_err(Error::kmerr)?;

        Ok(SecureDeletionSecretFile { object: object })
    }

    fn open() -> optee_utee::Result<SecureDeletionSecretFile> {
        let object = PersistentObject::open(
            ObjectStorageConstants::PrivateRee,
            SECURE_DELETION_SECRET_FILENAME.as_bytes(),
            DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE,
        )?;
        Ok(SecureDeletionSecretFile { object: object })
    }

    // Only for the factory reset secret: the other users need an existing file.
    fn open_or_create() -> Result<SecureDeletionSecretFile, kmr_common::Error> {
        match SecureDeletionSecretFile::open() {
            Ok(file) => Ok(file),
            Err(e) => match e.kind() {
                optee_utee::ErrorKind::ItemNotFound => SecureDeletionSecretFile::create(&[]),
                _ => Err(Error::kmerr(e)),
            },
        }
    }

    fn read_block<'buf>(
        &mut self,
        start: usize,
        buffer: &'buf mut [u8],
    ) -> Result<&'buf [u8], kmr_common::Error> {
        let req_len = buffer.len();

        self.object.seek(start as i32, Whence::DataSeekSet).map_err(Error::kmerr)?;
        let len = self.object.read(buffer).map_err(Error::kmerr)?;

        if len as usize != req_len {
            Err(km_err!(
                UnknownError,
                "couldn't read {} bytes of secure deletion secret file at offset {}. Read {} bytes",
                req_len,
                start,
                len
            ))
        } else {
            Ok(buffer)
        }
    }

    // Find empty slot is used to find the first [SECRET_SIZE] position on the secure file that
    // isn't currently in use. For this it will read the secure file in [BLOCK_SIZE] chunks and
    // move in [SECRET_SIZE] increments; checking if the IN_USE_FLAG is set on that position.
    fn find_empty_slot(&mut self, is_upgrade: bool) -> Result<Option<usize>, kmr_common::Error> {
        let end = SecureDeletionSecretFile::get_max_file_size(is_upgrade);
        let file_size = self.get_file_size()?;
        let end = cmp::min(end, file_size);
        let mut block_buffer = [0; BLOCK_SIZE];
        for start_pos in (0..end).step_by(BLOCK_SIZE) {
            let read_data = match self.read_block(start_pos, &mut block_buffer) {
                Ok(read_data) => read_data,
                Err(e) => {
                    error!("Failed to read block of secrets");
                    return Err(e);
                }
            };
            // Code assumes that we always read a complete block. API called could potentially
            // return less data.
            if read_data.len() != BLOCK_SIZE {
                return Err(km_err!(
                    SecureHwCommunicationFailed,
                    "failed to read complete block from storage. Received {} bytes",
                    read_data.len()
                ));
            }

            let block_start = match start_pos {
                FACTORY_RESET_SECRET_POS => FACTORY_FIRST_SECURE_DELETION_SECRET_POS,
                _ => 0,
            };

            for (chunk_num, secret) in read_data[block_start..].chunks(SECRET_SIZE).enumerate() {
                if (secret[0] & IN_USE_FLAG) == 0 {
                    let key_slot =
                        (start_pos + block_start + (chunk_num * SECRET_SIZE)) / SECRET_SIZE;
                    return Ok(Some(key_slot));
                }
            }
        }
        Ok(None)
    }

    fn write_block(&mut self, start: usize, buffer: &[u8]) -> Result<(), kmr_common::Error> {
        self.object.seek(start as i32, Whence::DataSeekSet).map_err(Error::kmerr)?;
        self.object.write(buffer).map_err(Error::kmerr)
    }

    fn get_file_size(&mut self) -> Result<usize, kmr_common::Error> {
        Ok(self.object.info().map_err(Error::kmerr)?.data_size())
    }

    fn get_max_file_size(is_upgrade: bool) -> usize {
        match is_upgrade {
            true => MAX_SECRET_FILE_SIZE_FOR_UPGRADES,
            false => MAX_SECRET_FILE_SIZE,
        }
    }

    fn resize(&mut self, new_size: usize) -> Result<(), kmr_common::Error> {
        self.object.truncate(new_size as u32).map_err(Error::kmerr)
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct FactoryResetSecret([u8; FACTORY_RESET_SECRET_SIZE]);

#[derive(Clone, PartialEq, Eq)]
pub struct SecureDeletionSecretManager {
    factory_reset_secret: RefCell<Option<FactoryResetSecret>>,
}

impl SecureDeletionSecretManager {
    pub fn new() -> Self {
        SecureDeletionSecretManager { factory_reset_secret: RefCell::new(None) }
    }

    fn get_factory_reset_secret_impl(
        &self,
    ) -> Result<RetrieveSecureDeletionSecretFileData, kmr_common::Error> {
        // Checking if we already have a cached secret we can return
        if let Some(secret) = self.factory_reset_secret.borrow_mut().deref_mut() {
            return Ok(RetrieveSecureDeletionSecretFileData::CachedDataFound(SecureDeletionData {
                factory_reset_secret: secret.0.clone(),
                secure_deletion_secret: [0; SECRET_SIZE],
            }));
        }

        // Looking now if we can read the secret from file
        let mut sdsf_file = SecureDeletionSecretFile::open_or_create()?;
        let file_size = sdsf_file.get_file_size().map_err(|e| {
            km_err!(
                SecureHwCommunicationFailed,
                "couldn't get secure deletion secret file size: {:?}",
                e
            )
        })?;

        // Found an empty file
        if file_size <= 0 {
            return Ok(RetrieveSecureDeletionSecretFileData::EmptyFileFound(sdsf_file));
        }

        // The file isn't empty, read the secret and cache it before returning the data
        debug!("Opened non-empty secure secrets file");
        let mut buffer = [0; FACTORY_RESET_SECRET_SIZE];
        let block = sdsf_file.read_block(FACTORY_RESET_SECRET_POS, &mut buffer)?;
        debug!("Read factory-reset secret, size {}", block.len());
        if block.len() != FACTORY_RESET_SECRET_SIZE {
            return Err(km_err!(
                SecureHwCommunicationFailed,
                "failed to read complete secret data from storage. Received {} bytes",
                block.len()
            ));
        }
        self.factory_reset_secret
            .borrow_mut()
            .deref_mut()
            .replace(FactoryResetSecret(buffer.clone()));
        Ok(RetrieveSecureDeletionSecretFileData::DataFoundOnFile(SecureDeletionData {
            factory_reset_secret: buffer,
            secure_deletion_secret: [0; SECRET_SIZE],
        }))
    }

    // get_or_create_factory_reset_secret_impl will use get_factory_reset_secret_impl to try to get
    // the factory reset secret. If the secure deletion secret file doesn't exist on secure storage,
    // it will create it and will also initialize it.
    fn get_or_create_factory_reset_secret_impl(
        &mut self,
        rng: &mut dyn crypto::Rng,
    ) -> Result<SecureDeletionData, kmr_common::Error> {
        let secret_file_data = self.get_factory_reset_secret_impl()?;
        match secret_file_data {
            RetrieveSecureDeletionSecretFileData::CachedDataFound(data) => Ok(data),
            RetrieveSecureDeletionSecretFileData::DataFoundOnFile(data) => Ok(data),
            RetrieveSecureDeletionSecretFileData::EmptyFileFound(sdsf_file) => {
                // Trusty initializes the file in a storage transaction. Here,
                // the first block is created at once instead, so that a crash
                // can't leave a file without its factory reset secret. The
                // empty file must be closed first, or OVERWRITE fails.
                drop(sdsf_file);
                let mut buffer = [0; FACTORY_RESET_SECRET_SIZE];
                rng.fill_bytes(&mut buffer);
                let mut block = [0; BLOCK_SIZE];
                block[FACTORY_RESET_SECRET_POS..FACTORY_FIRST_SECURE_DELETION_SECRET_POS]
                    .copy_from_slice(&buffer);
                let created = SecureDeletionSecretFile::create(&block);
                block.zeroize();
                created?;
                debug!("Committed new secrets file");
                self.factory_reset_secret
                    .borrow_mut()
                    .deref_mut()
                    .replace(FactoryResetSecret(buffer.clone()));
                Ok(SecureDeletionData {
                    factory_reset_secret: buffer,
                    secure_deletion_secret: [0; SECRET_SIZE],
                })
            }
        }
    }

    fn read_slot_data(
        &self,
        slot: SecureDeletionSlot,
        buffer: &mut [u8],
    ) -> Result<(), kmr_common::Error> {
        let buffer_size = buffer.len();
        if buffer_size != SECRET_SIZE {
            return Err(km_err!(
                InsufficientBufferSpace,
                "needed {} bytes to read slot, received {}",
                SECRET_SIZE,
                buffer.len()
            ));
        }
        let requested_slot = slot.0 as usize;
        let key_slot_pos = requested_slot * SECRET_SIZE;
        let mut sdsf_file = match SecureDeletionSecretFile::open() {
            Ok(sdsf_file) => sdsf_file,
            Err(e) => {
                error!("Failed to open file to get secure deletion data: {:?}", e);
                return Err(Error::kmerr(e));
            }
        };
        let file_size = match sdsf_file.get_file_size() {
            Ok(file_size) => file_size,
            Err(e) => {
                error!("Failed to read secure deletion data file size: {:?}", e);
                return Err(e);
            }
        };
        if (key_slot_pos + SECRET_SIZE) > file_size {
            return Err(km_err!(
                InvalidArgument,
                "invalid key slot {} would read past end of file of size {}",
                requested_slot,
                file_size
            ));
        }
        match sdsf_file.read_block(key_slot_pos, buffer) {
            Ok(read_data) => {
                if buffer_size == read_data.len() {
                    Ok(())
                } else {
                    Err(km_err!(
                        SecureHwCommunicationFailed,
                        "failed to read complete slot data from storage. Received {} bytes",
                        read_data.len()
                    ))
                }
            }
            Err(e) => {
                error!("Failed to read secret from slot {}: {:?}", requested_slot, e);
                Err(e)
            }
        }
    }
}

impl Drop for SecureDeletionSecretManager {
    fn drop(&mut self) {
        self.factory_reset_secret.borrow_mut().deref_mut().zeroize();
    }
}

impl ZeroizeOnDrop for SecureDeletionSecretManager {}

impl keyblob::SecureDeletionSecretManager for SecureDeletionSecretManager {
    fn get_or_create_factory_reset_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
    ) -> Result<SecureDeletionData, kmr_common::Error> {
        self.get_or_create_factory_reset_secret_impl(rng)
    }

    fn get_factory_reset_secret(&self) -> Result<SecureDeletionData, kmr_common::Error> {
        let secret_file_data = self.get_factory_reset_secret_impl()?;
        match secret_file_data {
            RetrieveSecureDeletionSecretFileData::CachedDataFound(data) => Ok(data),
            RetrieveSecureDeletionSecretFileData::DataFoundOnFile(data) => Ok(data),
            RetrieveSecureDeletionSecretFileData::EmptyFileFound(_) => {
                Err(km_err!(UnknownError, "factory reset secret not found"))
            }
        }
    }

    fn new_secret(
        &mut self,
        rng: &mut dyn crypto::Rng,
        slot_purpose: SlotPurpose,
    ) -> Result<(SecureDeletionSlot, SecureDeletionData), kmr_common::Error> {
        let is_upgrade = slot_purpose == SlotPurpose::KeyUpgrade;
        let mut secure_deletion_data = match self.get_or_create_factory_reset_secret_impl(rng) {
            Ok(data) => data,
            Err(e) => {
                info!("Unable to get factory reset secret: {:?}", e);
                return Err(e);
            }
        };
        rng.fill_bytes(&mut secure_deletion_data.secure_deletion_secret);
        secure_deletion_data.secure_deletion_secret[0] |= IN_USE_FLAG;
        // The factory reset secret was just read, so the secure storage is available.
        let mut sdsf_file = SecureDeletionSecretFile::open().map_err(Error::kmerr)?;
        let empty_slot = match sdsf_file.find_empty_slot(is_upgrade) {
            Ok(slot) => slot,
            Err(e) => {
                error!("Error while searching for key slot: {:?}", e);
                return Err(e);
            }
        };

        let original_file_size = sdsf_file.get_file_size()?;
        let empty_slot = match empty_slot {
            Some(slot_number) => slot_number,
            None => {
                // No empty slot found, try to increase file size
                let max_file_size = SecureDeletionSecretFile::get_max_file_size(is_upgrade);
                if original_file_size >= max_file_size {
                    error!(
                        "Didn't find a slot and can't grow the file larger than {}",
                        original_file_size
                    );
                    return Err(km_err!(
                        UnknownError,
                        "didn't find a slot and can't grow the file larger than {}",
                        original_file_size
                    ));
                }
                let new_size = original_file_size + BLOCK_SIZE;
                debug!("Attempting to resize file from {} to {}", original_file_size, new_size);
                if let Err(e) = sdsf_file.resize(new_size) {
                    error!("Failed to grow file to make room for a key slot: {:?}", e);
                    return Err(e);
                }
                // Truncating to a bigger size fills the new block with zeros.
                debug!("Resized file to {}", new_size);
                let slot_number = original_file_size / SECRET_SIZE;
                slot_number
            }
        };

        debug!("Writing new deletion secret to key slot {}", empty_slot);
        if let Err(e) = sdsf_file
            .write_block(empty_slot * SECRET_SIZE, &secure_deletion_data.secure_deletion_secret)
        {
            error!("Failed to write new deletion secret to key slot {}: {:?}", empty_slot, e);
            return Err(e);
        }
        debug!("Committed new secret");
        Ok((SecureDeletionSlot(empty_slot as u32), secure_deletion_data))
    }

    fn get_secret(
        &self,
        slot: SecureDeletionSlot,
    ) -> Result<SecureDeletionData, kmr_common::Error> {
        let mut current_try = 0;
        let mut secure_deletion_data = loop {
            let data = self.get_factory_reset_secret();
            if (data.is_ok()) || (current_try >= MAX_TRIES) {
                break data?;
            }
            current_try += 1;
        };
        let requested_slot = slot.0 as usize;
        if requested_slot == 0 || requested_slot == 1 {
            warn!("Requested slot {} which corresponds to factory reset secret", requested_slot);
            return Err(km_err!(
                InvalidArgument,
                "requested slot {} which does not contain a per-key secret",
                requested_slot
            ));
        }

        current_try = 0;
        loop {
            match self.read_slot_data(slot, &mut secure_deletion_data.secure_deletion_secret) {
                Ok(_) => {
                    debug!(
                        "Read secure deletion secret, size: {}",
                        secure_deletion_data.secure_deletion_secret.len()
                    );
                    break Ok(secure_deletion_data);
                }
                Err(e) => {
                    if current_try >= MAX_TRIES {
                        break Err(e);
                    }
                }
            }
            current_try += 1;
        }
    }

    fn delete_secret(&mut self, slot: SecureDeletionSlot) -> Result<(), kmr_common::Error> {
        let requested_slot = slot.0 as usize;
        if requested_slot == 0 || requested_slot == 1 {
            debug!("key_slot == {}, nothing to delete", requested_slot);
            return Err(km_err!(
                InvalidArgument,
                "requested slot {} which does not contain a per-key secret",
                requested_slot
            ));
        }
        let key_slot_start = requested_slot * SECRET_SIZE;
        let key_slot_end = key_slot_start + SECRET_SIZE;
        if key_slot_start < FACTORY_FIRST_SECURE_DELETION_SECRET_POS {
            // This should be unhittable (the test for slot 0 or 1 above will trigger) but keep
            // in just in case of future arithmetic errors.
            return Err(km_err!(
                InvalidArgument,
                "attempted to delete invalid key slot {}",
                requested_slot
            ));
        }
        // Unlike Trusty, which retries forever, give up after MAX_TRIES: this
        // single-instance TA would otherwise hang for every client.
        for _ in 0..MAX_TRIES {
            let mut sdsf_file = match SecureDeletionSecretFile::open() {
                Ok(sdsf_file) => sdsf_file,
                // No file: the slot was already deleted, by delete_all().
                Err(e) if e.kind() == optee_utee::ErrorKind::ItemNotFound => {
                    return Err(km_err!(
                        InvalidArgument,
                        "attempted to delete invalid key slot {}",
                        requested_slot
                    ));
                }
                Err(e) => {
                    error!("Failed to open file to retrieve secure deletion data: {:?}", e);
                    continue;
                }
            };
            let file_size = match sdsf_file.get_file_size() {
                Ok(size) => size,
                Err(_) => continue,
            };
            if key_slot_end > file_size {
                return Err(km_err!(
                    InvalidArgument,
                    "attempted to delete invalid key slot {}",
                    requested_slot
                ));
            }
            if let Err(_) = sdsf_file.write_block(key_slot_start, &[0; SECRET_SIZE]) {
                continue;
            }
            debug!(
                "Deleted secure key slot {}, zeroing {} to {}",
                requested_slot, key_slot_start, key_slot_end
            );
            debug!("Committed deletion");
            return Ok(());
        }
        Err(km_err!(SecureHwCommunicationFailed, "couldn't delete key slot {}", requested_slot))
    }

    fn delete_all(&mut self) {
        self.factory_reset_secret.borrow_mut().take();
        // Give up after MAX_TRIES, as in delete_secret().
        for _ in 0..MAX_TRIES {
            match delete_secure_deletion_secret_file() {
                Ok(_) => return,
                Err(e) => error!("Couldn't delete file. Received error: {:?}", e),
            }
        }
        error!("Gave up deleting the secure deletion secret file");
    }
}
