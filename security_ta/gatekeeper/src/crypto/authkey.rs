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

//! Auth token key management via KeyMint TA.
//!
//! Signs HardwareAuthTokens with the key that the KeyMint TA agreed through
//! ISharedSecret. The key changes at each boot, and whenever the negotiation
//! runs again, so it is fetched from the KeyMint TA at each sign() call and
//! never cached. sign() fails until the negotiation has run.
//!
//! Protocol:
//!   - Open session to KeyMint TA
//!   - Invoke KM_GET_AUTHTOKEN_KEY (0x10000)
//!   - param[1]: 32-byte MemrefOutput buffer, filled with the key

use crate::invoke;
use alloc::vec::Vec;
use gk_ta::traits::{self, OpaqueOr};
use gk_ta::Error as GkError;

/// Auth key management implementation that retrieves the key from the KeyMint TA.
pub struct AuthKey {
    /// HMAC-SHA256 implementation used for signing.
    hmac: alloc::boxed::Box<dyn traits::HmacSha256>,
}

impl AuthKey {
    pub fn new(hmac: alloc::boxed::Box<dyn traits::HmacSha256>) -> Self {
        AuthKey { hmac }
    }
}

impl traits::AuthKeyManagement for AuthKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, GkError> {
        let key = OpaqueOr::Explicit(invoke::get_keymint_auth_token_key()?);
        self.hmac.sign(&key, data)
    }
}
