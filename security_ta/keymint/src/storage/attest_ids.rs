//
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

//! Attestation IDs, provisioned once in secure storage.
//!
//! The file holds the CBOR-encoded `AttestationIdInfo`.

use crate::error::Error;
use alloc::vec;
use core::sync::atomic::{AtomicBool, Ordering};
use kmr_common::{
    km_err,
    wire::{AsCborValue, AttestationIdInfo},
};
use kmr_ta::device::RetrieveAttestationIds;
use log::{error, info};
use optee_utee::{DataFlag, ErrorKind, GenericObject, ObjectStorageConstants, PersistentObject};

const ATTESTATION_IDS_FILENAME: &str = "AttestationIds_1";

/// Set once the IDs are known to be missing, so that each key
/// generation does not go back to secure storage. Cleared by `provision()`.
static IDS_ABSENT: AtomicBool = AtomicBool::new(false);

/// Store the attestation IDs. Fails with `AccessConflict` if they were already
/// provisioned.
pub fn provision(ids: AttestationIdInfo) -> optee_utee::Result<()> {
    if ids == AttestationIdInfo::default() {
        error!("No attestation ID to provision");
        return Err(optee_utee::Error::new(ErrorKind::BadParameters));
    }
    let data = ids.into_vec().map_err(|_| optee_utee::Error::new(ErrorKind::BadParameters))?;
    // Without DataFlag::OVERWRITE, the creation fails if the file exists.
    PersistentObject::create(
        ObjectStorageConstants::PrivateRee,
        ATTESTATION_IDS_FILENAME.as_bytes(),
        DataFlag::ACCESS_READ,
        None,
        &data,
    )
    .map_err(|e| {
        error!("Cannot provision the attestation IDs: {e}");
        e
    })?;
    IDS_ABSENT.store(false, Ordering::Relaxed);
    info!("Attestation IDs provisioned");
    Ok(())
}

fn read() -> Result<Option<AttestationIdInfo>, kmr_common::Error> {
    if IDS_ABSENT.load(Ordering::Relaxed) {
        return Ok(None);
    }
    let ids = read_storage()?;
    if ids.is_none() {
        IDS_ABSENT.store(true, Ordering::Relaxed);
    }
    Ok(ids)
}

fn read_storage() -> Result<Option<AttestationIdInfo>, kmr_common::Error> {
    let object = match PersistentObject::open(
        ObjectStorageConstants::PrivateRee,
        ATTESTATION_IDS_FILENAME.as_bytes(),
        DataFlag::ACCESS_READ,
    ) {
        Ok(object) => object,
        Err(e) if e.kind() == ErrorKind::ItemNotFound => return Ok(None),
        Err(e) => return Err(Error::kmerr(e)),
    };
    let size = object.info().map_err(Error::kmerr)?.data_size();
    if size > crate::KEYMINT_MAX_BUFFER_LENGTH {
        return Err(km_err!(UnknownError, "attestation IDs file too large: {size}"));
    }
    let mut data = vec![0u8; size];
    let len = object.read(&mut data).map_err(Error::kmerr)? as usize;
    AttestationIdInfo::from_slice(&data[..len])
        .map(Some)
        .map_err(|e| km_err!(UnknownError, "cannot decode the attestation IDs: {e:?}"))
}

/// Attestation IDs from secure storage, `None` until provisioned.
pub struct AttestationIds;

impl RetrieveAttestationIds for AttestationIds {
    fn get(&self) -> Result<AttestationIdInfo, kmr_common::Error> {
        read()?.ok_or_else(|| km_err!(AttestationIdsNotProvisioned, "attestation IDs not provisioned"))
    }

    fn get_ids(&self) -> Result<Option<AttestationIdInfo>, kmr_common::Error> {
        read()
    }

    /// Deprecated in the KeyMint AIDL, which requires UNIMPLEMENTED.
    fn destroy_all(&mut self) -> Result<(), kmr_common::Error> {
        Err(km_err!(Unimplemented, "destroying the attestation IDs is not supported"))
    }
}
