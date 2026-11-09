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

use crate::error::Error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use kmr_common::{crypto, km_err, vec_try};
use kmr_wire::keymint::Digest;
use optee_utee::{
    AlgorithmId, AttributeId, AttributeMemref, Mac, TransientObject, TransientObjectType,
};
use zeroize::Zeroizing;

struct MacOperation {
    mac: Mac,
    len: usize,
}

// SAFETY: The raw pointer to TEE_OperationHandle is held only by us, so
// it can be safely transferred to another thread.
unsafe impl Send for MacOperation {}

impl crypto::AccumulatingOperation for MacOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        self.mac.update(data);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let mut output = vec_try![0u8; self.len]?;
        self.mac.compute_final(&[0u8; 0], output.as_mut_slice()).map_err(Error::kmerr)?;
        Ok(output)
    }
}

pub struct Hmac;

impl crypto::Hmac for Hmac {
    fn begin(
        &self,
        key: crypto::OpaqueOr<crypto::hmac::Key>,
        digest: Digest,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, kmr_common::Error> {
        // min_key_bytes: smallest HMAC key OP-TEE accepts for this digest
        let (algorithm, keytype, output_len, min_key_bytes) = match &digest {
            Digest::Md5 => Ok((AlgorithmId::HmacMd5, TransientObjectType::HmacMd5, 16, 8)),
            Digest::Sha1 => Ok((AlgorithmId::HmacSha1, TransientObjectType::HmacSha1, 20, 10)),
            Digest::Sha224 => {
                Ok((AlgorithmId::HmacSha224, TransientObjectType::HmacSha224, 28, 14))
            }
            Digest::Sha256 => {
                Ok((AlgorithmId::HmacSha256, TransientObjectType::HmacSha256, 32, 24))
            }
            Digest::Sha384 => {
                Ok((AlgorithmId::HmacSha384, TransientObjectType::HmacSha384, 48, 32))
            }
            Digest::Sha512 => {
                Ok((AlgorithmId::HmacSha512, TransientObjectType::HmacSha512, 64, 32))
            }
            digest => Err(km_err!(UnsupportedDigest, "Unknown digest {:?}", digest)),
        }?;
        let key = kmr_common::explicit!(key)?;

        // HMAC (RFC 2104) right-pads the key with zeros to the hash block size
        let mut padded = Zeroizing::new(vec_try![0u8; key.0.len().max(min_key_bytes)]?);
        padded[..key.0.len()].copy_from_slice(&key.0);
        let key_size_bits = padded.len() * 8;

        // TEE_SetOperationKey copies the key: keyobj is freed on return.
        let mut keyobj = TransientObject::allocate(keytype, key_size_bits).map_err(Error::kmerr)?;
        let attr = AttributeMemref::from_ref(AttributeId::SecretValue, padded.as_slice());
        keyobj.populate(&[attr.into()]).map_err(Error::kmerr)?;

        // Use key_size_bits for max_key_size parameter, not output_len
        let mac = Mac::allocate(algorithm, key_size_bits).map_err(Error::kmerr)?;
        mac.set_key(&keyobj).map_err(Error::kmerr)?;
        mac.init(&[0u8; 0]);

        Ok(Box::new(MacOperation { mac, len: output_len }))
    }
}

pub struct AesCmac;

impl crypto::AesCmac for AesCmac {
    fn begin(
        &self,
        key: crypto::OpaqueOr<crypto::aes::Key>,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, kmr_common::Error> {
        let key = kmr_common::explicit!(key)?;
        let (keybuf, keysize_in_bits) = match &key {
            crypto::aes::Key::Aes128(k) => (&k[..], 128),
            crypto::aes::Key::Aes192(k) => (&k[..], 192),
            crypto::aes::Key::Aes256(k) => (&k[..], 256),
        };

        let mut keyobj = TransientObject::allocate(TransientObjectType::Aes, key.size().0 as usize)
            .map_err(Error::kmerr)?;
        let attr = AttributeMemref::from_ref(AttributeId::SecretValue, keybuf);
        keyobj.populate(&[attr.into()]).map_err(Error::kmerr)?;

        let mac = Mac::allocate(AlgorithmId::AesCmac, keysize_in_bits).map_err(Error::kmerr)?;
        mac.set_key(&keyobj).map_err(Error::kmerr)?;
        mac.init(&[0u8; 0]);

        Ok(Box::new(MacOperation { mac, len: crypto::aes::BLOCK_SIZE }))
    }
}
