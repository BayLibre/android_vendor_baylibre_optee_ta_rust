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

//! Password key retrieval using a hardware-backed key derived from the HBK.
//!
//! Uses the OP-TEE system PTA's PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY command to
//! derive a 32-byte key that is unique to this TA and bound to the hardware.
//! This key persists across factory resets because it is derived from the
//! hardware unique key, which is required for Gatekeeper's factory reset
//! protection semantics.

use crate::invoke;
use gk_ta::traits::{self, HmacKey, OpaqueOr};
use gk_ta::Error as GkError;

/// Derivation label for the Gatekeeper password key.
/// Must remain stable so the same key is derived on each boot.
const PASSWORD_KEY_DERIVATION_DATA: &[u8] = b"GatekeeperPasswordKey\0";

/// Size of the derived password key in bytes.
const PASSWORD_KEY_SIZE: usize = 32;

/// Password key retrieval implementation backed by the OP-TEE hardware unique key.
///
/// The key is derived fresh each time `key()` is called using the system PTA,
/// which ensures it is always bound to the hardware without needing to store it.
pub struct PasswordKey;

impl traits::PasswordKeyRetrieval for PasswordKey {
    fn key(&self) -> Result<OpaqueOr<HmacKey>, GkError> {
        let raw_key = invoke::derive_hbk(PASSWORD_KEY_DERIVATION_DATA, PASSWORD_KEY_SIZE)?;
        Ok(OpaqueOr::Explicit(HmacKey(raw_key)))
    }
}
