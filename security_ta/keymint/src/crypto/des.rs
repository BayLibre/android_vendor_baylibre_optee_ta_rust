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

use crate::crypto::operation::{
    BlockCipher, BlockOperation, Pkcs7DecryptOperation, Pkcs7EncryptOperation,
};
use crate::error::Error;
use alloc::boxed::Box;
use kmr_common::crypto;
use optee_utee::{
    AlgorithmId, AttributeId, AttributeMemref, Cipher, OperationMode, TransientObject,
    TransientObjectType,
};

pub struct Des;

impl crypto::Des for Des {
    fn begin(
        &self,
        key: crypto::OpaqueOr<crypto::des::Key>,
        mode: crypto::des::Mode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::EmittingOperation>, kmr_common::Error> {
        let operation = match &dir {
            crypto::SymmetricOperation::Encrypt => OperationMode::Encrypt,
            crypto::SymmetricOperation::Decrypt => OperationMode::Decrypt,
        };

        let (algorithm, nonce) = match &mode {
            crypto::des::Mode::EcbNoPadding | crypto::des::Mode::EcbPkcs7Padding => {
                (AlgorithmId::Des3EcbNopad, &[0u8; 0][..])
            }
            crypto::des::Mode::CbcNoPadding { nonce: n }
            | crypto::des::Mode::CbcPkcs7Padding { nonce: n } => {
                (AlgorithmId::Des3CbcNopad, &n[..])
            }
        };

        let key = kmr_common::explicit!(key)?;
        let size_in_bits = crypto::des::KEY_SIZE_BITS.0 as usize;
        let mut keyobj = TransientObject::allocate(TransientObjectType::Des3, size_in_bits)
            .map_err(Error::kmerr)?;
        let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &key.0[..]);
        keyobj.populate(&[attr.into()]).map_err(Error::kmerr)?;

        let cipher = Cipher::allocate(algorithm, operation, size_in_bits).map_err(Error::kmerr)?;
        cipher.set_key(&keyobj).map_err(Error::kmerr)?;
        cipher.init(nonce);

        match mode {
            crypto::des::Mode::EcbPkcs7Padding
            | crypto::des::Mode::CbcPkcs7Padding { nonce: _ } => match dir {
                crypto::SymmetricOperation::Encrypt => {
                    Ok(Box::new(Pkcs7EncryptOperation::new(crypto::des::BLOCK_SIZE, cipher)))
                }
                crypto::SymmetricOperation::Decrypt => {
                    Ok(Box::new(Pkcs7DecryptOperation::new(crypto::des::BLOCK_SIZE, cipher)))
                }
            },
            _ => Ok(Box::new(BlockOperation::new(
                crypto::des::BLOCK_SIZE,
                BlockCipher::Block(cipher),
            ))),
        }
    }
}
