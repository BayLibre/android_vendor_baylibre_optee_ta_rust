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

//! HMAC-SHA256 implementation using OP-TEE's MAC API.

use alloc::vec::Vec;
use gk_ta::traits::{self, HmacKey, OpaqueOr};
use gk_ta::Error as GkError;
use optee_utee::{
    AlgorithmId, AttributeId, AttributeMemref, Mac, TransientObject, TransientObjectType,
};

/// HMAC-SHA256 implementation backed by OP-TEE's TEE_AllocateOperation MAC API.
pub struct HmacSha256;

impl traits::HmacSha256 for HmacSha256 {
    fn sign(&self, key: &OpaqueOr<HmacKey>, data: &[u8]) -> Result<Vec<u8>, GkError> {
        let key_bytes = match key {
            OpaqueOr::Explicit(k) => &k.0,
            OpaqueOr::Opaque(_) => return Err(GkError::Unimplemented),
        };

        let key_size_bits = key_bytes.len() * 8;

        // Allocate a transient key object for HMAC-SHA256
        let mut keyobj = TransientObject::allocate(TransientObjectType::HmacSha256, key_size_bits)
            .map_err(|e| {
                log::error!("Failed to allocate HMAC-SHA256 key object: {}", e);
                GkError::Internal
            })?;

        let attr = AttributeMemref::from_ref(AttributeId::SecretValue, key_bytes.as_slice());
        keyobj.populate(&[attr.into()]).map_err(|e| {
            log::error!("Failed to populate HMAC-SHA256 key: {}", e);
            GkError::Internal
        })?;

        // Allocate HMAC-SHA256 operation using key_size_bits as max_key_size
        let mac = Mac::allocate(AlgorithmId::HmacSha256, key_size_bits).map_err(|e| {
            log::error!("Failed to allocate HMAC-SHA256 operation: {}", e);
            GkError::Internal
        })?;

        mac.set_key(&keyobj).map_err(|e| {
            log::error!("Failed to set HMAC-SHA256 key: {}", e);
            GkError::Internal
        })?;

        mac.init(&[]);

        // SHA-256 produces 32 bytes
        const SHA256_OUTPUT_LEN: usize = 32;
        let mut output = alloc::vec![0u8; SHA256_OUTPUT_LEN];

        mac.compute_final(data, output.as_mut_slice()).map_err(|e| {
            log::error!("Failed to compute HMAC-SHA256: {}", e);
            GkError::Internal
        })?;

        Ok(output)
    }
}
