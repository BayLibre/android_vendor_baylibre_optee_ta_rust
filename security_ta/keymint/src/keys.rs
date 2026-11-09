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

//! Root keys, derived from the hardware unique key.

use kmr_common::{crypto, Error};
use kmr_ta::device::RetrieveKeyMaterial;

const ROOT_KEK_SIZE: usize = 32;
const ROOT_KEK_DERIVATION_DATA: &'static [u8] = b"KeymasterMaster\0";

const KAK_SIZE: usize = 32;
const KAK_DERIVATION_DATA: &'static [u8] = b"KeymintKeyAgreementKey\0";

pub struct Keys;

impl RetrieveKeyMaterial for Keys {
    fn root_kek(&self, _context: &[u8]) -> Result<crypto::OpaqueOr<crypto::hmac::Key>, Error> {
        let key = crate::crypto::derive_hbk(ROOT_KEK_DERIVATION_DATA, ROOT_KEK_SIZE)?;
        Ok(crypto::hmac::Key::new(key.0.clone()).into())
    }

    fn kak(&self) -> Result<crypto::OpaqueOr<crypto::aes::Key>, Error> {
        // In a real implementation with multiple TEEs (e.g. Strongbox), KAK
        // is provisioned to the device. With only a single TEE, deriving a
        // hardware-backed key is sufficient.
        let key = crate::crypto::derive_hbk(KAK_DERIVATION_DATA, KAK_SIZE)?;
        Ok(crypto::aes::Key::Aes256(key.0.clone().try_into().unwrap()).into())
    }
}
