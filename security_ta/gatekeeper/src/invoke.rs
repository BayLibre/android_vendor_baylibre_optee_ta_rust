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

//! Gatekeeper TA IPC helpers — thin wrappers over optee-ipc-ta that map
//! `optee_utee::Error` to `gk_ta::Error`, plus Gatekeeper-specific
//! PTA/TA functions.

use crate::error::utee_to_gk_err;
use alloc::vec::Vec;
use gk_ta::traits::HmacKey;
use gk_ta::Error as GkError;
use optee_utee::Uuid;
use zeroize::Zeroizing;

use optee_ipc_ta::{Direction, Param, Params};

// KeyMint command to retrieve the auth token HMAC key.
// Must match GET_AUTH_TOKEN_KEY in security_ta/keymint/src/command.rs.
pub const KM_GET_AUTHTOKEN_KEY: u32 = 0x10000;

pub const AUTH_KEY_SIZE: usize = 32;

pub struct Session(optee_ipc_ta::Session);

impl Session {
    pub fn invoke(&self, command: u32, params: &Params) -> Result<u32, GkError> {
        self.0.invoke(command, params).map_err(utee_to_gk_err)
    }
}

pub struct Ta;

impl Ta {
    pub fn open(uuid: &Uuid, params: &Params) -> Result<Session, GkError> {
        optee_ipc_ta::open(uuid, params).map(Session).map_err(utee_to_gk_err)
    }

    pub fn open_keymint_ta(params: &Params) -> Result<Session, GkError> {
        Self::open(&Uuid::from(optee_ta_common::KEYMINT_TA_UUID), params)
    }
}

/// Derive a hardware-bound key via the OP-TEE system PTA.
///
/// Uses PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY which generates a key unique to this
/// TA and bound to the device hardware.
pub fn derive_hbk(input: &[u8], len: usize) -> Result<Vec<u8>, GkError> {
    let mut key = alloc::vec![0u8; len];
    optee_ipc_ta::derive_ta_unique_key(input, &mut key).map_err(utee_to_gk_err)?;
    Ok(key)
}

/// Retrieve the 32-byte auth token HMAC key from the KeyMint TA.
pub fn get_keymint_auth_token_key() -> Result<HmacKey, GkError> {
    let mut params = Param::empty();
    let session = Ta::open_keymint_ta(&params)?;

    // Wiped on drop, on the error paths too.
    let mut key = Zeroizing::new([0u8; AUTH_KEY_SIZE]);
    params.1 = Param::from_mut_slice(key.as_mut_slice(), Direction::Out);
    session.invoke(KM_GET_AUTHTOKEN_KEY, &params)?;

    Ok(HmacKey(key.to_vec()))
}
