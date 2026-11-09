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
use kmr_common::{crypto, km_err, vec_try, FallibleAllocExt};

pub struct AE {
    tag_len: usize,
    pub cipher: optee_utee::AE,
}

impl AE {
    pub fn new(tag_len: usize, cipher: optee_utee::AE) -> Self {
        Self { tag_len: tag_len, cipher: cipher }
    }

    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
}

pub enum BlockCipher {
    Block(optee_utee::Cipher),
    Counter(optee_utee::Cipher),
    AEncrypt(AE),
    ADecrypt(AE),
}

pub struct BlockOperation {
    block_size: usize,
    input_len: usize,
    cipher: BlockCipher,
}

// SAFETY: The raw pointer to TEE_OperationHandle is held only by us, so
// it can be safely transferred to another thread.
unsafe impl Send for BlockOperation {}

impl BlockOperation {
    pub fn new(block_size: usize, cipher: BlockCipher) -> Self {
        Self { block_size: block_size, input_len: 0, cipher: cipher }
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn input_len(&self) -> usize {
        self.input_len
    }

    pub fn cipher(&self) -> Result<&optee_utee::Cipher, kmr_common::Error> {
        match &self.cipher {
            BlockCipher::Block(cipher) | BlockCipher::Counter(cipher) => Ok(cipher),
            _ => Err(km_err!(Unimplemented, "Expected BlockCipher::Cipher or Counter")),
        }
    }

    pub fn ae(&self) -> Result<&AE, kmr_common::Error> {
        match &self.cipher {
            BlockCipher::AEncrypt(ae) | BlockCipher::ADecrypt(ae) => Ok(ae),
            _ => Err(km_err!(Unimplemented, "Expected BlockCipher::A*crypt")),
        }
    }
}

impl crypto::AadOperation for BlockOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), kmr_common::Error> {
        self.ae()?.cipher.update_aad(aad);
        Ok(())
    }
}

impl crypto::EmittingOperation for BlockOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, kmr_common::Error> {
        let mut output = vec_try![0u8; data.len() + self.block_size]?;
        self.input_len += data.len();

        let len = match &self.cipher {
            BlockCipher::Block(cipher) | BlockCipher::Counter(cipher) => {
                cipher.update(data, output.as_mut_slice())
            }
            BlockCipher::AEncrypt(ae) | BlockCipher::ADecrypt(ae) => {
                ae.cipher.update(data, output.as_mut_slice())
            }
        }
        .map_err(Error::kmerr)?;

        output.truncate(len);
        Ok(output)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let mut output = vec_try![0u8; 2 * self.block_size]?;

        match self.cipher {
            BlockCipher::Block(cipher) => {
                if (self.input_len % self.block_size) != 0 {
                    return Err(km_err!(
                        InvalidInputLength,
                        "Input length not multiple of block size"
                    ));
                }

                let len = cipher.do_final(&[], output.as_mut_slice()).map_err(Error::kmerr)?;

                output.truncate(len);
                Ok(output)
            }
            BlockCipher::Counter(cipher) => {
                let len = cipher.do_final(&[], output.as_mut_slice()).map_err(Error::kmerr)?;

                output.truncate(len);
                Ok(output)
            }
            BlockCipher::AEncrypt(ae) => {
                let mut tag = vec_try![0u8; ae.tag_len]?;

                let (output_len, tag_len) = ae
                    .cipher
                    .encrypt_final(&[], output.as_mut_slice(), tag.as_mut_slice())
                    .map_err(Error::kmerr)?;

                output.truncate(output_len);
                output.try_extend_from_slice(tag.as_slice())?;

                if tag_len != ae.tag_len {
                    Err(km_err!(InvalidTag, "Invalid tag length"))
                } else {
                    Ok(output)
                }
            }
            BlockCipher::ADecrypt(_) => {
                Err(km_err!(Unimplemented, "Owner must implement EmittingOperation::finish"))
            }
        }
    }
}

pub struct BufferedOperation {
    inner: BlockOperation,
    max_size: usize,
    pub buffer: Vec<u8>,
}

impl BufferedOperation {
    pub fn new(max_size: usize, block_size: usize, cipher: BlockCipher) -> Self {
        Self {
            inner: BlockOperation::new(block_size, cipher),
            max_size: max_size,
            buffer: Vec::new(),
        }
    }

    pub fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    pub fn input_len(&self) -> usize {
        self.inner.input_len()
    }

    pub fn cipher(&self) -> Result<&optee_utee::Cipher, kmr_common::Error> {
        self.inner.cipher()
    }

    pub fn ae(&self) -> Result<&AE, kmr_common::Error> {
        self.inner.ae()
    }
}

impl crypto::AadOperation for BufferedOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), kmr_common::Error> {
        self.inner.update_aad(aad)
    }
}

impl crypto::EmittingOperation for BufferedOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, kmr_common::Error> {
        // Delay outputting the final max_size bytes until finish()
        self.buffer.try_extend_from_slice(data)?;

        if self.buffer.len() > self.max_size {
            self.inner.update(
                self.buffer
                    .drain(..self.buffer.len() - self.max_size)
                    .collect::<Vec<u8>>()
                    .as_slice(),
            )
        } else {
            Ok(Vec::new())
        }
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        Err(km_err!(Unimplemented, "Owner must implement EmittingOperation::finish"))
    }
}

pub struct Pkcs7EncryptOperation {
    inner: BlockOperation,
}

impl Pkcs7EncryptOperation {
    pub fn new(block_size: usize, cipher: optee_utee::Cipher) -> Self {
        Self { inner: BlockOperation::new(block_size, BlockCipher::Block(cipher)) }
    }

    fn get_padding(&self) -> Result<Vec<u8>, kmr_common::Error> {
        let padding = self.inner.block_size() - (self.inner.input_len() % self.inner.block_size());
        Ok(vec_try![padding as u8; padding]?)
    }
}

impl crypto::EmittingOperation for Pkcs7EncryptOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, kmr_common::Error> {
        self.inner.update(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let padding = self.get_padding()?;
        let mut output = vec_try![0u8; 2 * self.inner.block_size()]?;

        let len = self
            .inner
            .cipher()?
            .do_final(padding.as_slice(), output.as_mut_slice())
            .map_err(Error::kmerr)?;

        output.truncate(len);
        Ok(output)
    }
}

pub struct Pkcs7DecryptOperation {
    inner: BufferedOperation,
}

impl Pkcs7DecryptOperation {
    pub fn new(block_size: usize, cipher: optee_utee::Cipher) -> Self {
        Self { inner: BufferedOperation::new(block_size, block_size, BlockCipher::Block(cipher)) }
    }

    fn validate_padding(&self, data: &mut Vec<u8>) -> Result<usize, kmr_common::Error> {
        let output_len = data.len();
        if output_len < 1 {
            return Err(km_err!(InvalidInputLength, "Input too short for padding"));
        }

        let padding_len = data[output_len - 1] as usize;
        if padding_len == 0 || padding_len > self.inner.block_size() {
            return Err(km_err!(InvalidArgument, "Invalid padding length {}", padding_len));
        }

        let unpadded_len = output_len - padding_len;
        let mut padding: Vec<_> = data.drain(unpadded_len..).collect();
        padding.retain(|&x| x == padding_len as u8);

        if padding.len() != padding_len {
            return Err(km_err!(InvalidArgument, "Invalid padding"));
        }

        Ok(unpadded_len)
    }
}

impl crypto::EmittingOperation for Pkcs7DecryptOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, kmr_common::Error> {
        self.inner.update(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let input_len = self.inner.input_len() + self.inner.buffer.len();
        if input_len < self.inner.block_size() || (input_len % self.inner.block_size()) != 0 {
            return Err(km_err!(InvalidInputLength, "Input length not multiple of block size"));
        }

        let mut output = vec_try![0u8; 2 * self.inner.block_size()]?;

        let len = self
            .inner
            .cipher()?
            .do_final(self.inner.buffer.as_slice(), output.as_mut_slice())
            .map_err(Error::kmerr)?;

        output.truncate(len);
        self.validate_padding(&mut output)?;
        Ok(output)
    }
}
