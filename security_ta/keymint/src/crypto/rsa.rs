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

use crate::crypto::digest_to_algid;
use crate::error::Error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use der::SecretDocument;
use kmr_common::{crypto, km_err, vec_try, FallibleAllocExt};
use kmr_wire::keymint::Digest;
use optee_utee::{
    AlgorithmId, Asymmetric, AttributeId, AttributeMemref, GenericObject, OperationMode,
    TransientObject, TransientObjectType,
};
use pkcs1::{RsaPrivateKey, UintRef};

macro_rules! attr_to_uintref {
    ($obj:ident, $attrid:ident) => {
        UintRef::new(Rsa::get_key_attribute(&$obj, AttributeId::$attrid)?.0.as_slice())
            .map_err(Error::kmerr)?
    };
}

macro_rules! attr_from_uintref {
    ($field:expr, $attrid:ident) => {
        AttributeMemref::from_ref(AttributeId::$attrid, $field.as_bytes()).into()
    };
}

pub struct Rsa;

impl Rsa {
    fn get_key_attribute(
        obj: &TransientObject,
        id: AttributeId,
    ) -> Result<crypto::RawKeyMaterial, kmr_common::Error> {
        let mut buf = vec_try![0u8; 512]?;
        let len = obj.ref_attribute(id, buf.as_mut_slice()).map_err(Error::kmerr)?;
        buf.truncate(len);
        Ok(crypto::RawKeyMaterial(buf))
    }

    fn get_private_key_from_der(
        key: &crypto::rsa::Key,
    ) -> Result<TransientObject, kmr_common::Error> {
        let size_in_bits = key.size() * 8;
        let key = RsaPrivateKey::try_from(key.0.as_slice()).map_err(Error::kmerr)?;
        let mut obj = TransientObject::allocate(TransientObjectType::RsaKeypair, size_in_bits)
            .map_err(Error::kmerr)?;

        obj.populate(&[
            attr_from_uintref!(key.modulus, RsaModulus),
            attr_from_uintref!(key.public_exponent, RsaPublicExponent),
            attr_from_uintref!(key.private_exponent, RsaPrivateExponent),
            attr_from_uintref!(key.prime1, RsaPrime1),
            attr_from_uintref!(key.prime2, RsaPrime2),
            attr_from_uintref!(key.exponent1, RsaExponent1),
            attr_from_uintref!(key.exponent2, RsaExponent2),
            attr_from_uintref!(key.coefficient, RsaCoefficient),
        ])
        .map_err(Error::kmerr)?;

        Ok(obj)
    }

    fn zero_pad_left(data: &[u8], len: usize) -> Result<Vec<u8>, kmr_common::Error> {
        let mut dest = vec_try![0; len]?;
        let padding_len = len - data.len();
        dest[padding_len..].copy_from_slice(data);
        Ok(dest)
    }
}

impl crypto::Rsa for Rsa {
    fn generate_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        key_size: kmr_wire::KeySizeInBits,
        pub_exponent: kmr_wire::RsaExponent,
        _params: &[kmr_wire::keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, kmr_common::Error> {
        let size_in_bits = key_size.0 as usize;
        let exp = pub_exponent.0.to_be_bytes().to_vec();
        let exp = AttributeMemref::from_ref(AttributeId::RsaPublicExponent, &exp);
        let obj = TransientObject::allocate(TransientObjectType::RsaKeypair, size_in_bits)
            .map_err(Error::kmerr)?;
        obj.generate_key(size_in_bits, &[exp.into()]).map_err(Error::kmerr)?;

        let der: SecretDocument = RsaPrivateKey {
            modulus: attr_to_uintref!(obj, RsaModulus),
            public_exponent: attr_to_uintref!(obj, RsaPublicExponent),
            private_exponent: attr_to_uintref!(obj, RsaPrivateExponent),
            prime1: attr_to_uintref!(obj, RsaPrime1),
            prime2: attr_to_uintref!(obj, RsaPrime2),
            exponent1: attr_to_uintref!(obj, RsaExponent1),
            exponent2: attr_to_uintref!(obj, RsaExponent2),
            coefficient: attr_to_uintref!(obj, RsaCoefficient),
            other_prime_infos: None,
        }
        .try_into()
        .map_err(Error::kmerr)?;

        Ok(crypto::KeyMaterial::Rsa(crypto::rsa::Key(der.as_bytes().into()).into()))
    }

    fn begin_decrypt(
        &self,
        key: crypto::OpaqueOr<crypto::rsa::Key>,
        mode: crypto::rsa::DecryptionMode,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, kmr_common::Error> {
        let (decrypt_algid, mgf_algid) = match mode {
            crypto::rsa::DecryptionMode::OaepPadding { msg_digest, mgf_digest } => {
                let decrypt_algid = match msg_digest {
                    Digest::Md5 => Ok(AlgorithmId::RsaesPkcs1OAepMgf1MD5),
                    Digest::Sha1 => Ok(AlgorithmId::RsaesPkcs1OAepMgf1Sha1),
                    Digest::Sha224 => Ok(AlgorithmId::RsaesPkcs1OAepMgf1Sha224),
                    Digest::Sha256 => Ok(AlgorithmId::RsaesPkcs1OAepMgf1Sha256),
                    Digest::Sha384 => Ok(AlgorithmId::RsaesPkcs1OAepMgf1Sha384),
                    Digest::Sha512 => Ok(AlgorithmId::RsaesPkcs1OAepMgf1Sha512),
                    digest => Err(km_err!(
                        UnsupportedAlgorithm,
                        "Unsupported OAEP message digest: {:?}",
                        digest
                    )),
                }?;

                let mgf_algid = if let Some(algid) = digest_to_algid(mgf_digest) {
                    Ok(algid)
                } else {
                    Err(km_err!(
                        UnsupportedAlgorithm,
                        "Unsupported OAEP MGF1 digest: {:?}",
                        mgf_digest
                    ))
                }?;

                Ok::<(AlgorithmId, Option<AlgorithmId>), kmr_common::Error>((
                    decrypt_algid,
                    Some(mgf_algid),
                ))
            }
            crypto::rsa::DecryptionMode::Pkcs1_1_5Padding => Ok((AlgorithmId::RsaesPkcs1V15, None)),
            crypto::rsa::DecryptionMode::NoPadding => Ok((AlgorithmId::RsaNopad, None)),
        }?;
        let key = kmr_common::explicit!(key)?;
        let max_size = key.size();

        Ok(Box::new(RsaDecryptOperation {
            key: key,
            max_size: max_size,
            algid: decrypt_algid,
            mgf_algid: mgf_algid,
            pending_input: Vec::new(),
        }))
    }

    fn begin_sign(
        &self,
        key: crypto::OpaqueOr<crypto::rsa::Key>,
        mode: crypto::rsa::SignMode,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, kmr_common::Error> {
        let key = kmr_common::explicit!(key)?;

        let (sign_algid, digest_algid, max_size) = match mode {
            crypto::rsa::SignMode::NoPadding => Ok((AlgorithmId::RsaNopad, None, None)),
            crypto::rsa::SignMode::PssPadding(digest) => match digest {
                Digest::Md5 => {
                    Ok((AlgorithmId::RsassaPkcs1PssMgf1MD5, Some(AlgorithmId::Md5), None))
                }
                Digest::Sha1 => {
                    Ok((AlgorithmId::RsassaPkcs1PssMgf1Sha1, Some(AlgorithmId::Sha1), None))
                }
                Digest::Sha224 => {
                    Ok((AlgorithmId::RsassaPkcs1PssMgf1Sha224, Some(AlgorithmId::Sha224), None))
                }
                Digest::Sha256 => {
                    Ok((AlgorithmId::RsassaPkcs1PssMgf1Sha256, Some(AlgorithmId::Sha256), None))
                }
                Digest::Sha384 => {
                    Ok((AlgorithmId::RsassaPkcs1PssMgf1Sha384, Some(AlgorithmId::Sha384), None))
                }
                Digest::Sha512 => {
                    Ok((AlgorithmId::RsassaPkcs1PssMgf1Sha512, Some(AlgorithmId::Sha512), None))
                }
                digest => Err(km_err!(
                    UnsupportedAlgorithm,
                    "Unsupported RSA PSS signature hash algorithm: {:?}",
                    digest
                )),
            },
            crypto::rsa::SignMode::Pkcs1_1_5Padding(digest) => match digest {
                Digest::None => Ok((
                    AlgorithmId::RsassaPkcs1V15,
                    None,
                    Some(key.size() - crypto::rsa::PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD),
                )),
                Digest::Md5 => Ok((AlgorithmId::RsassaPkcs1V15MD5, Some(AlgorithmId::Md5), None)),
                Digest::Sha1 => {
                    Ok((AlgorithmId::RsassaPkcs1V15Sha1, Some(AlgorithmId::Sha1), None))
                }
                Digest::Sha224 => {
                    Ok((AlgorithmId::RsassaPkcs1V15Sha224, Some(AlgorithmId::Sha224), None))
                }
                Digest::Sha256 => {
                    Ok((AlgorithmId::RsassaPkcs1V15Sha256, Some(AlgorithmId::Sha256), None))
                }
                Digest::Sha384 => {
                    Ok((AlgorithmId::RsassaPkcs1V15Sha384, Some(AlgorithmId::Sha384), None))
                }
                Digest::Sha512 => {
                    Ok((AlgorithmId::RsassaPkcs1V15Sha512, Some(AlgorithmId::Sha512), None))
                }
            },
        }?;

        if let Some(digest) = digest_algid {
            Ok(Box::new(RsaSignDigestOperation {
                key: key,
                algid: sign_algid,
                digest: optee_utee::Digest::allocate(digest).map_err(Error::kmerr)?,
            }))
        } else {
            let max_size = match max_size {
                Some(size) => size,
                None => key.size(),
            };

            match sign_algid {
                AlgorithmId::RsaNopad => Ok(Box::new(RsaDecryptOperation {
                    key: key,
                    max_size: max_size,
                    algid: sign_algid,
                    mgf_algid: None,
                    pending_input: Vec::new(),
                })),
                _ => Ok(Box::new(RsaSignOperation {
                    key: key,
                    max_size: max_size,
                    algid: sign_algid,
                    pending_input: Vec::new(),
                })),
            }
        }
    }
}

struct RsaDecryptOperation {
    key: crypto::rsa::Key,
    max_size: usize,
    algid: AlgorithmId,
    mgf_algid: Option<AlgorithmId>,
    pending_input: Vec<u8>,
}

impl crypto::AccumulatingOperation for RsaDecryptOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(self.max_size)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let key = Rsa::get_private_key_from_der(&self.key)?;

        let pad = match &self.algid {
            AlgorithmId::RsaNopad => true,
            _ => false,
        };

        let cipher = Asymmetric::allocate(self.algid, OperationMode::Decrypt, self.key.size() * 8)
            .map_err(Error::kmerr)?;
        cipher.set_key(&key).map_err(Error::kmerr)?;

        let input = if pad {
            Rsa::zero_pad_left(&self.pending_input, self.key.size())?
        } else {
            self.pending_input
        };

        let output = if let Some(algid) = self.mgf_algid {
            cipher.decrypt(
                &[AttributeMemref::from_ref(
                    AttributeId::RsaOaepMgf1Hash,
                    &(algid as u32).to_ne_bytes(),
                )
                .into()],
                input.as_slice(),
            )
        } else {
            cipher.decrypt(&[], input.as_slice())
        }
        .map_err(Error::kmerr)?;

        if pad {
            Ok(Rsa::zero_pad_left(&output, self.key.size())?)
        } else {
            Ok(output)
        }
    }
}

struct RsaSignOperation {
    key: crypto::rsa::Key,
    max_size: usize,
    algid: AlgorithmId,
    pending_input: Vec<u8>,
}

impl crypto::AccumulatingOperation for RsaSignOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(self.max_size)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let key = Rsa::get_private_key_from_der(&self.key)?;

        let cipher = Asymmetric::allocate(self.algid, OperationMode::Sign, self.key.size() * 8)
            .map_err(Error::kmerr)?;
        cipher.set_key(&key).map_err(Error::kmerr)?;

        let mut signature = vec_try![0u8; 2048]?;
        let len = cipher
            .sign_digest(&[], self.pending_input.as_slice(), signature.as_mut_slice())
            .map_err(Error::kmerr)?;
        signature.truncate(len);

        Ok(signature)
    }
}
struct RsaSignDigestOperation {
    key: crypto::rsa::Key,
    algid: AlgorithmId,
    digest: optee_utee::Digest,
}

// SAFETY: The raw pointer to TEE_OperationHandle is held only by us, so
// it can be safely transferred to another thread.
unsafe impl Send for RsaSignDigestOperation {}

impl crypto::AccumulatingOperation for RsaSignDigestOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        self.digest.update(data);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let key = Rsa::get_private_key_from_der(&self.key)?;

        let mut digest = vec_try![0u8; 64]?;
        let len = self.digest.do_final(&[], digest.as_mut_slice()).map_err(Error::kmerr)?;
        digest.truncate(len);

        let cipher = Asymmetric::allocate(self.algid, OperationMode::Sign, self.key.size() * 8)
            .map_err(Error::kmerr)?;
        cipher.set_key(&key).map_err(Error::kmerr)?;

        let mut signature = vec_try![0u8; 2048]?;
        let len = cipher
            .sign_digest(&[], digest.as_slice(), signature.as_mut_slice())
            .map_err(Error::kmerr)?;
        signature.truncate(len);

        Ok(signature)
    }
}
