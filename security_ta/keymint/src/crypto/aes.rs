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

use crate::crypto::operation;
use crate::crypto::operation::{
    BlockCipher, BlockOperation, BufferedOperation, Pkcs7DecryptOperation, Pkcs7EncryptOperation,
};
use crate::error::Error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use kmr_common::{crypto, km_err, vec_try};
use optee_utee::{
    AlgorithmId, AttributeId, AttributeMemref, Cipher, OperationMode, TransientObject,
    TransientObjectType, AE,
};

pub struct Aes;

impl crypto::Aes for Aes {
    fn begin(
        &self,
        key: crypto::OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::CipherMode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::EmittingOperation>, kmr_common::Error> {
        let operation = match &dir {
            crypto::SymmetricOperation::Encrypt => OperationMode::Encrypt,
            crypto::SymmetricOperation::Decrypt => OperationMode::Decrypt,
        };

        let (algorithm, nonce) = match &mode {
            crypto::aes::CipherMode::EcbNoPadding | crypto::aes::CipherMode::EcbPkcs7Padding => {
                (AlgorithmId::AesEcbNopad, &[0u8; 0][..])
            }
            crypto::aes::CipherMode::CbcNoPadding { nonce: n }
            | crypto::aes::CipherMode::CbcPkcs7Padding { nonce: n } => {
                (AlgorithmId::AesCbcNopad, &n[..])
            }
            crypto::aes::CipherMode::Ctr { nonce: n } => (AlgorithmId::AesCtr, &n[..]),
        };

        let key = kmr_common::explicit!(key)?;
        let keybuf = match &key {
            crypto::aes::Key::Aes128(k) => &k[..],
            crypto::aes::Key::Aes192(k) => &k[..],
            crypto::aes::Key::Aes256(k) => &k[..],
        };

        let mut keyobj = TransientObject::allocate(TransientObjectType::Aes, key.size().0 as usize)
            .map_err(Error::kmerr)?;
        let attr = AttributeMemref::from_ref(AttributeId::SecretValue, keybuf);
        keyobj.populate(&[attr.into()]).map_err(Error::kmerr)?;

        let cipher =
            Cipher::allocate(algorithm, operation, key.size().0 as usize).map_err(Error::kmerr)?;
        cipher.set_key(&keyobj).map_err(Error::kmerr)?;
        cipher.init(nonce);

        match mode {
            crypto::aes::CipherMode::EcbPkcs7Padding
            | crypto::aes::CipherMode::CbcPkcs7Padding { nonce: _ } => match dir {
                crypto::SymmetricOperation::Encrypt => {
                    Ok(Box::new(Pkcs7EncryptOperation::new(crypto::aes::BLOCK_SIZE, cipher)))
                }
                crypto::SymmetricOperation::Decrypt => {
                    Ok(Box::new(Pkcs7DecryptOperation::new(crypto::aes::BLOCK_SIZE, cipher)))
                }
            },
            crypto::aes::CipherMode::Ctr { nonce: _ } => Ok(Box::new(BlockOperation::new(
                crypto::aes::BLOCK_SIZE,
                BlockCipher::Counter(cipher),
            ))),
            _ => Ok(Box::new(BlockOperation::new(
                crypto::aes::BLOCK_SIZE,
                BlockCipher::Block(cipher),
            ))),
        }
    }

    fn begin_aead(
        &self,
        key: crypto::OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::GcmMode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::AadOperation>, kmr_common::Error> {
        let operation = match &dir {
            crypto::SymmetricOperation::Encrypt => OperationMode::Encrypt,
            crypto::SymmetricOperation::Decrypt => OperationMode::Decrypt,
        };

        let (tag_len, nonce) = match &mode {
            crypto::aes::GcmMode::GcmTag12 { nonce: n }
            | crypto::aes::GcmMode::GcmTag13 { nonce: n }
            | crypto::aes::GcmMode::GcmTag14 { nonce: n }
            | crypto::aes::GcmMode::GcmTag15 { nonce: n }
            | crypto::aes::GcmMode::GcmTag16 { nonce: n } => (mode.tag_len() * 8, &n[..]),
        };

        let key = kmr_common::explicit!(key)?;
        let keybuf = match &key {
            crypto::aes::Key::Aes128(k) => &k[..],
            crypto::aes::Key::Aes192(k) => &k[..],
            crypto::aes::Key::Aes256(k) => &k[..],
        };

        let mut keyobj = TransientObject::allocate(TransientObjectType::Aes, key.size().0 as usize)
            .map_err(Error::kmerr)?;
        let attr = AttributeMemref::from_ref(AttributeId::SecretValue, keybuf);
        keyobj.populate(&[attr.into()]).map_err(Error::kmerr)?;

        let cipher = AE::allocate(AlgorithmId::AesGcm, operation, key.size().0 as usize)
            .map_err(Error::kmerr)?;
        cipher.set_key(&keyobj).map_err(Error::kmerr)?;
        cipher.init(nonce, tag_len, 0, 0).map_err(Error::kmerr)?;

        let tag_bytes = tag_len / 8;
        match &dir {
            crypto::SymmetricOperation::Encrypt => Ok(Box::new(BlockOperation::new(
                crypto::aes::BLOCK_SIZE,
                BlockCipher::AEncrypt(operation::AE::new(tag_bytes, cipher)),
            ))),
            crypto::SymmetricOperation::Decrypt => {
                Ok(Box::new(AesGcmDecryptOperation::new(tag_bytes, cipher)))
            }
        }
    }
}

struct AesGcmDecryptOperation {
    inner: BufferedOperation,
}

impl AesGcmDecryptOperation {
    pub fn new(tag_len: usize, cipher: AE) -> Self {
        Self {
            inner: BufferedOperation::new(
                tag_len,
                crypto::aes::BLOCK_SIZE,
                BlockCipher::ADecrypt(operation::AE::new(tag_len, cipher)),
            ),
        }
    }
}

impl crypto::AadOperation for AesGcmDecryptOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), kmr_common::Error> {
        self.inner.update_aad(aad)
    }
}

impl crypto::EmittingOperation for AesGcmDecryptOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, kmr_common::Error> {
        self.inner.update(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let ae = self.inner.ae()?;
        if self.inner.buffer.len() != ae.tag_len() {
            return Err(km_err!(InvalidInputLength, "Input too short (<tag size)"));
        }

        let mut output = vec_try![0u8; 2 * self.inner.block_size()]?;
        let len = ae
            .cipher
            .decrypt_final(&[], output.as_mut_slice(), self.inner.buffer.as_slice())
            .map_err(Error::kmerr)?;

        output.truncate(len);
        Ok(output)
    }
}
