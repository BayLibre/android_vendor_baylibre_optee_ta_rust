//
// Copyright (C) 2024 The Android Open Source Project
// Copyright (C) 2026 BayLibre
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

//! Persistent storage for Gatekeeper failure records using OP-TEE PersistentObject API.
//!
//! Implements the `SecureFilesystem` trait from `gk_ta::traits`, which in turn
//! provides a blanket implementation of `FailureRecording`.
//!
//! Files are stored in OP-TEE's private secure storage, which is tied to this TA's
//! identity and is not accessible by other TAs or the normal world.

use alloc::string::String;
use alloc::vec::Vec;
use gk_ta::traits;
use gk_ta::Error as GkError;
use log::error;
use optee_utee::{
    DataFlag, GenericObject, ObjectEnumHandle, ObjectStorageConstants,
    PersistentObject, Whence,
};

/// Secure filesystem implementation using OP-TEE's PersistentObject API.
///
/// Each file is stored as a separate PersistentObject in OP-TEE's private storage.
/// The object ID is the filename as a UTF-8 byte slice.
pub struct SecureStorage;

impl traits::SecureFilesystem for SecureStorage {
    type Iter = alloc::vec::IntoIter<String>;

    fn read(&self, filename: &str) -> Result<Vec<u8>, GkError> {
        let obj = match PersistentObject::open(
            ObjectStorageConstants::PrivateRee,
            filename.as_bytes(),
            DataFlag::ACCESS_READ,
        ) {
            Ok(o) => o,
            Err(e) => {
                if e.kind() == optee_utee::ErrorKind::ItemNotFound {
                    return Err(GkError::NotFound);
                }
                error!("storage::read: failed to open '{}': {}", filename, e);
                return Err(GkError::Internal);
            }
        };

        // Determine the data size from object info
        let info = obj.info().map_err(|e| {
            error!("storage::read: failed to get info for '{}': {}", filename, e);
            GkError::Internal
        })?;

        let data_size = info.data_size();
        let mut buf = alloc::vec![0u8; data_size];

        if data_size == 0 {
            return Ok(buf);
        }

        obj.seek(0, Whence::DataSeekSet).map_err(|e| {
            error!("storage::read: seek failed for '{}': {}", filename, e);
            GkError::Internal
        })?;

        let bytes_read = obj.read(buf.as_mut_slice()).map_err(|e| {
            error!("storage::read: read failed for '{}': {}", filename, e);
            GkError::Internal
        })?;

        if bytes_read as usize != data_size {
            error!(
                "storage::read: short read for '{}': expected {} got {}",
                filename, data_size, bytes_read
            );
            return Err(GkError::Internal);
        }

        Ok(buf)
    }

    fn write(&self, filename: &str, data: &[u8]) -> Result<(), GkError> {
        // Creating with OVERWRITE replaces the object atomically: a crash
        // leaves either the old record or the new one.
        PersistentObject::create(
            ObjectStorageConstants::PrivateRee,
            filename.as_bytes(),
            DataFlag::ACCESS_WRITE | DataFlag::OVERWRITE,
            None,
            data,
        )
        .map(|_| ())
        .map_err(|e| {
            error!("storage::write: create failed for '{}': {}", filename, e);
            GkError::Internal
        })
    }

    fn delete(&self, filename: &str) -> Result<(), GkError> {
        match PersistentObject::open(
            ObjectStorageConstants::PrivateRee,
            filename.as_bytes(),
            DataFlag::ACCESS_WRITE_META,
        ) {
            Ok(obj) => obj.close_and_delete().map_err(|e| {
                error!("storage::delete: close_and_delete failed for '{}': {}", filename, e);
                GkError::Internal
            }),
            Err(e) if e.kind() == optee_utee::ErrorKind::ItemNotFound => Err(GkError::NotFound),
            Err(e) => {
                error!("storage::delete: open failed for '{}': {}", filename, e);
                Err(GkError::Internal)
            }
        }
    }

    fn list(&self) -> Result<Self::Iter, GkError> {
        let mut names: Vec<String> = Vec::new();

        let mut enumerator = ObjectEnumHandle::allocate().map_err(|e| {
            error!("storage::list: allocate enumerator failed: {}", e);
            GkError::Internal
        })?;

        // Start enumeration; TEE_ERROR_ITEM_NOT_FOUND means empty storage
        match enumerator.start(ObjectStorageConstants::PrivateRee as u32) {
            Ok(_) => {}
            Err(e) if e.kind() == optee_utee::ErrorKind::ItemNotFound => {
                // Empty storage is OK - return empty iterator
                return Ok(names.into_iter());
            }
            Err(e) => {
                error!("storage::list: start enumerator failed: {}", e);
                return Err(GkError::Internal);
            }
        }

        // Maximum object ID length in OP-TEE is 64 bytes (TEE_OBJECT_ID_MAX_LEN)
        let mut id_buf = [0u8; 64];
        loop {
            match enumerator.get_next(None, &mut id_buf) {
                Ok(id_len) => {
                    let id_slice = &id_buf[..id_len as usize];
                    match core::str::from_utf8(id_slice) {
                        Ok(name) => {
                            names.push(String::from(name));
                        }
                        Err(_) => {
                            log::warn!("storage::list: non-UTF8 object ID, skipping");
                        }
                    }
                }
                Err(e) if e.kind() == optee_utee::ErrorKind::ItemNotFound => {
                    // No more objects
                    break;
                }
                Err(e) => {
                    error!("storage::list: get_next failed: {}", e);
                    return Err(GkError::Internal);
                }
            }
        }

        Ok(names.into_iter())
    }
}
