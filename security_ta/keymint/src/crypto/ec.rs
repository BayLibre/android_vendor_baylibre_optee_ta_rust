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

use crate::crypto::{digest_to_algid, nist_point};
use crate::error::Error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use der::SecretDocument;
use ed25519_dalek as ed25519;
use ed25519_dalek::Signer;
use kmr_common::crypto::ec::{Ed25519Key, Key, NistCurve, NistKey, X25519Key};
use kmr_common::crypto::{CurveType, KeyMaterial, OpaqueOr, RawKeyMaterial};
use kmr_common::{crypto, km_err, vec_try, FallibleAllocExt};
use kmr_wire::keymint::{Digest, EcCurve};
use optee_utee::{
    AlgorithmId, Asymmetric, AttributeId, AttributeMemref, AttributeValue, DeriveKey, ElementId,
    GenericObject, OperationMode, TransientObject, TransientObjectType,
};
use pkcs8::{ObjectIdentifier, SubjectPublicKeyInfoRef};
use sec1::{point::ModulusSize, EcParameters, EcPrivateKey, EncodedPoint};
use typenum::{U28, U32, U48, U66};
use x25519_dalek as x25519;

pub struct Ec;

impl Ec {
    const MAX_DIGEST_LEN: usize = 64;
    const MAX_SIGNATURE_LEN: usize = 132;
    // https://android.googlesource.com/platform/system/keymint/+/refs/heads/main/boringssl/src/ec.rs#145
    const MAX_SPKI_LEN: usize = 164;

    fn get_attribute(
        obj: &TransientObject,
        id: AttributeId,
        size: usize,
    ) -> Result<RawKeyMaterial, kmr_common::Error> {
        // OP-TEE drops the leading zero bytes of big numbers (e.g. 65 vs 66
        // bytes for P521), so left-pad the value to `size` bytes.
        let mut buf = vec_try![0u8; size]?;
        let len = obj.ref_attribute(id, &mut buf).map_err(Error::kmerr)?;
        if len > size {
            return Err(km_err!(InvalidInputLength, "Unexpected key attribute length: {}", len));
        }
        // The bytes after `len` are zero: move them to the front.
        buf.rotate_right(size - len);
        Ok(RawKeyMaterial(buf))
    }

    fn nist_curve_to_sign_algid(curve: NistCurve) -> AlgorithmId {
        match curve {
            NistCurve::P224 => AlgorithmId::EcDsaSha224,
            NistCurve::P256 => AlgorithmId::EcDsaSha256,
            NistCurve::P384 => AlgorithmId::EcDsaSha384,
            NistCurve::P521 => AlgorithmId::EcDsaSha512,
        }
    }

    fn nist_curve_to_id(curve: NistCurve) -> ElementId {
        match curve {
            NistCurve::P224 => ElementId::EccCurveNistP224,
            NistCurve::P256 => ElementId::EccCurveNistP256,
            NistCurve::P384 => ElementId::EccCurveNistP384,
            NistCurve::P521 => ElementId::EccCurveNistP521,
        }
    }

    fn nist_curve_to_oid(curve: NistCurve) -> ObjectIdentifier {
        match curve {
            NistCurve::P224 => crypto::ec::ALGO_PARAM_P224_OID,
            NistCurve::P256 => crypto::ec::ALGO_PARAM_P256_OID,
            NistCurve::P384 => crypto::ec::ALGO_PARAM_P384_OID,
            NistCurve::P521 => crypto::ec::ALGO_PARAM_P521_OID,
        }
    }

    fn nist_public_key_to_coordinates(
        key: &[u8],
        curve: NistCurve,
    ) -> Result<(Vec<u8>, Vec<u8>), kmr_common::Error> {
        match curve {
            NistCurve::P224 => Ec::point_to_coordinates::<U28>(key),
            NistCurve::P256 => Ec::point_to_coordinates::<U32>(key),
            NistCurve::P384 => Ec::point_to_coordinates::<U48>(key),
            NistCurve::P521 => Ec::point_to_coordinates::<U66>(key),
        }
    }

    fn point_to_coordinates<Size: ModulusSize>(
        key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), kmr_common::Error> {
        let point = EncodedPoint::<Size>::try_from(key).map_err(Error::kmerr)?;
        // Compressed and identity points have no y coordinate.
        match (point.x(), point.y()) {
            (Some(x), Some(y)) => Ok((x.to_vec(), y.to_vec())),
            _ => Err(km_err!(InvalidArgument, "Not an uncompressed point")),
        }
    }

    fn nist_private_key_from_der(
        key: &[u8],
        curve: NistCurve,
        object_type: TransientObjectType,
    ) -> Result<TransientObject, kmr_common::Error> {
        let epk = EcPrivateKey::try_from(key).map_err(Error::kmerr)?;
        if curve.coord_len() != epk.private_key.len() {
            return Err(km_err!(
                InvalidKeyBlob,
                "Unexpected private key size: {}",
                epk.private_key.len()
            ));
        }
        if epk.public_key.is_none() {
            return Err(km_err!(InvalidKeyBlob, "Missing NIST public key"));
        }
        let (public_x, public_y) =
            Ec::nist_public_key_to_coordinates(epk.public_key.unwrap(), curve)?;

        let mut private_key = TransientObject::allocate(
            object_type,
            crypto::ec::curve_to_key_size(curve.into()).0 as usize,
        )
        .map_err(Error::kmerr)?;
        private_key
            .populate(&[
                AttributeMemref::from_ref(AttributeId::EccPrivateValue, epk.private_key).into(),
                AttributeMemref::from_ref(AttributeId::EccPublicValueX, public_x.as_slice()).into(),
                AttributeMemref::from_ref(AttributeId::EccPublicValueY, public_y.as_slice()).into(),
                AttributeValue::from_value(
                    AttributeId::EccCurve,
                    Ec::nist_curve_to_id(curve) as u32,
                    0,
                )
                .into(),
            ])
            .map_err(Error::kmerr)?;
        Ok(private_key)
    }
}

impl crypto::Ec for Ec {
    fn generate_nist_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        curve: NistCurve,
        _params: &[kmr_wire::keymint::KeyParam],
    ) -> Result<KeyMaterial, kmr_common::Error> {
        let size_in_bits = crypto::ec::curve_to_key_size(curve.into()).0 as usize;
        let obj = TransientObject::allocate(TransientObjectType::EcdsaKeypair, size_in_bits)
            .map_err(Error::kmerr)?;
        let curve_attr = AttributeValue::from_value(
            AttributeId::EccCurve,
            Ec::nist_curve_to_id(curve) as u32,
            0,
        );
        obj.generate_key(size_in_bits, &[curve_attr.into()]).map_err(Error::kmerr)?;

        let private_key = Ec::get_attribute(&obj, AttributeId::EccPrivateValue, curve.coord_len())?;
        let public_x = Ec::get_attribute(&obj, AttributeId::EccPublicValueX, curve.coord_len())?;
        let public_y = Ec::get_attribute(&obj, AttributeId::EccPublicValueY, curve.coord_len())?;

        let public_key: Vec<u8> = match curve {
            NistCurve::P224 => EncodedPoint::<U28>::from_affine_coordinates(
                public_x.0.as_slice().try_into().map_err(Error::kmerr)?,
                public_y.0.as_slice().try_into().map_err(Error::kmerr)?,
                false,
            )
            .as_bytes()
            .try_into(),
            NistCurve::P256 => EncodedPoint::<U32>::from_affine_coordinates(
                public_x.0.as_slice().try_into().map_err(Error::kmerr)?,
                public_y.0.as_slice().try_into().map_err(Error::kmerr)?,
                false,
            )
            .as_bytes()
            .try_into(),
            NistCurve::P384 => EncodedPoint::<U48>::from_affine_coordinates(
                public_x.0.as_slice().try_into().map_err(Error::kmerr)?,
                public_y.0.as_slice().try_into().map_err(Error::kmerr)?,
                false,
            )
            .as_bytes()
            .try_into(),
            NistCurve::P521 => EncodedPoint::<U66>::from_affine_coordinates(
                public_x.0.as_slice().try_into().map_err(Error::kmerr)?,
                public_y.0.as_slice().try_into().map_err(Error::kmerr)?,
                false,
            )
            .as_bytes()
            .try_into(),
        }
        .map_err(Error::kmerr)?;

        let der: SecretDocument = EcPrivateKey {
            private_key: private_key.0.as_slice(),
            parameters: Some(EcParameters::NamedCurve(Ec::nist_curve_to_oid(curve))),
            public_key: Some(public_key.as_slice()),
        }
        .try_into()
        .map_err(Error::kmerr)?;

        let key = match curve {
            NistCurve::P224 => Key::P224(NistKey(der.as_bytes().into())),
            NistCurve::P256 => Key::P256(NistKey(der.as_bytes().into())),
            NistCurve::P384 => Key::P384(NistKey(der.as_bytes().into())),
            NistCurve::P521 => Key::P521(NistKey(der.as_bytes().into())),
        };

        Ok(KeyMaterial::Ec(curve.into(), CurveType::Nist, OpaqueOr::Explicit(key)))
    }

    fn generate_ed25519_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        _params: &[kmr_wire::keymint::KeyParam],
    ) -> Result<KeyMaterial, kmr_common::Error> {
        let size_in_bits = crypto::ec::curve_to_key_size(EcCurve::Curve25519).0 as usize;
        let obj = TransientObject::allocate(TransientObjectType::Ed25519Keypair, size_in_bits)
            .map_err(Error::kmerr)?;
        obj.generate_key(size_in_bits, &[]).map_err(Error::kmerr)?;

        let private_value =
            Ec::get_attribute(&obj, AttributeId::Ed25519PrivateValue, size_in_bits / 8)?;
        let key = Ed25519Key(private_value.0.as_slice().try_into().map_err(Error::kmerr)?);

        // TransientObject contains a public key attribute, but Keymint expects us to return
        // only the private key. Confirm that we can recompute the public key because the GP
        // API does not have native support for key operations.
        let expected_public_key =
            Ec::get_attribute(&obj, AttributeId::Ed25519PublicValue, size_in_bits / 8)?;
        let computed_public_key = self.ed25519_public_key(&key)?;

        if expected_public_key.0 != computed_public_key {
            return Err(km_err!(UnsupportedEcCurve, "Failed to compute Ed25519 public key"));
        }

        Ok(KeyMaterial::Ec(EcCurve::Curve25519, CurveType::EdDsa, Key::Ed25519(key).into()))
    }

    fn generate_x25519_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        _params: &[kmr_wire::keymint::KeyParam],
    ) -> Result<KeyMaterial, kmr_common::Error> {
        let size_in_bits = crypto::ec::curve_to_key_size(EcCurve::Curve25519).0 as usize;
        let obj = TransientObject::allocate(TransientObjectType::X25519Keypair, size_in_bits)
            .map_err(Error::kmerr)?;
        obj.generate_key(size_in_bits, &[]).map_err(Error::kmerr)?;
        let private_value =
            Ec::get_attribute(&obj, AttributeId::X25519PrivateValue, size_in_bits / 8)?;
        let key = X25519Key(private_value.0.as_slice().try_into().map_err(Error::kmerr)?);

        // TransientObject contains a public key attribute, but Keymint expects us to return
        // only the private key. Confirm that we can recompute the public key because the GP
        // API does not have native support for key operations.
        let expected_public_key =
            Ec::get_attribute(&obj, AttributeId::X25519PublicValue, size_in_bits / 8)?;
        let computed_public_key = self.x25519_public_key(&key)?;

        if expected_public_key.0 != computed_public_key {
            return Err(km_err!(UnsupportedEcCurve, "Failed to compute X25519 public key"));
        }

        Ok(KeyMaterial::Ec(EcCurve::Curve25519, CurveType::Xdh, Key::X25519(key).into()))
    }

    fn nist_public_key(
        &self,
        key: &NistKey,
        _curve: NistCurve,
    ) -> Result<Vec<u8>, kmr_common::Error> {
        let key = EcPrivateKey::try_from(key.0.as_slice()).map_err(Error::kmerr)?;
        match key.public_key {
            // generate_nist_key included the public key in the private key DER, so we should
            // never have to recompute the key.
            Some(public_key) => Ok(public_key.into()),
            // publicKey is optional in ECPrivateKey (RFC 5915), and the GP API
            // can't compute it from the private key.
            None => Err(km_err!(InvalidArgument, "NIST private key without public key")),
        }
    }

    fn ed25519_public_key(&self, key: &Ed25519Key) -> Result<Vec<u8>, kmr_common::Error> {
        Ok(ed25519::SigningKey::from_bytes(&key.0).verifying_key().as_bytes().into())
    }

    fn x25519_public_key(&self, key: &X25519Key) -> Result<Vec<u8>, kmr_common::Error> {
        let secret = x25519::StaticSecret::from(key.0);
        Ok(x25519::PublicKey::from(&secret).as_bytes().into())
    }

    fn begin_agree(
        &self,
        key: OpaqueOr<Key>,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, kmr_common::Error> {
        Ok(Box::new(EcAgreeOperation {
            key: kmr_common::explicit!(key)?,
            pending_input: Vec::new(),
        }))
    }

    fn begin_sign(
        &self,
        key: OpaqueOr<Key>,
        digest: Digest,
    ) -> Result<Box<dyn crypto::AccumulatingOperation>, kmr_common::Error> {
        let key = kmr_common::explicit!(key)?;
        match key.curve_type() {
            CurveType::Nist => {
                let curve = NistCurve::try_from(key.curve())?;
                let sign_algid = Ec::nist_curve_to_sign_algid(curve);

                if let Some(digest_algid) = digest_to_algid(digest) {
                    Ok(Box::new(EcDsaSignDigestOperation {
                        key: key,
                        algid: sign_algid,
                        digest: optee_utee::Digest::allocate(digest_algid).map_err(Error::kmerr)?,
                    }))
                } else {
                    Ok(Box::new(EcDsaSignOperation {
                        key: key,
                        max_size: curve.coord_len(),
                        algid: sign_algid,
                        pending_input: Vec::new(),
                    }))
                }
            }
            CurveType::EdDsa => {
                Ok(Box::new(Ed25519SignOperation { key: key, pending_input: Vec::new() }))
            }
            _ => Err(km_err!(IncompatibleAlgorithm, "Key not valid for signing")),
        }
    }
}

struct EcAgreeOperation {
    key: Key,
    pending_input: Vec<u8>,
}

impl crypto::AccumulatingOperation for EcAgreeOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(Ec::MAX_SPKI_LEN)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let spki = SubjectPublicKeyInfoRef::try_from(self.pending_input.as_slice())
            .map_err(Error::kmerr)?;

        match self.key {
            Key::P224(ref key) | Key::P256(ref key) | Key::P384(ref key) | Key::P521(ref key) => {
                if spki.algorithm.oid != crypto::ec::X509_NIST_OID
                    || spki.algorithm.parameters.is_none()
                {
                    return Err(km_err!(InvalidArgument, "Incompatible peer key"));
                }

                let curve = NistCurve::try_from(self.key.curve())?;
                let peer_oid: ObjectIdentifier = spki
                    .algorithm
                    .parameters
                    .unwrap()
                    .decode_as()
                    .map_err(|_| km_err!(InvalidArgument, "Peer key has no OID parameter"))?;

                if peer_oid != Ec::nist_curve_to_oid(curve) {
                    return Err(km_err!(InvalidArgument, "Incompatible peer key"));
                }

                let private_key = Ec::nist_private_key_from_der(
                    key.0.as_slice(),
                    curve,
                    TransientObjectType::EcdhKeypair,
                )?;

                let peer_key = spki.subject_public_key.as_bytes();
                if peer_key.is_none() {
                    return Err(km_err!(InvalidKeyBlob, "Peer public key not octet aligned"));
                }
                let (peer_x, peer_y) = Ec::nist_public_key_to_coordinates(peer_key.unwrap(), curve)
                    .map_err(|_| km_err!(InvalidArgument, "Peer public key is invalid"))?;
                // TEE_DeriveKey does not check the peer point before OP-TEE
                // c2d64e1390 (invalid curve attack), and panics after it.
                nist_point::check_point(curve, &peer_x, &peer_y)?;

                let secret_size_in_bits = curve.coord_len() * 8;
                let mut shared = TransientObject::allocate(
                    TransientObjectType::GenericSecret,
                    secret_size_in_bits,
                )
                .map_err(Error::kmerr)?;
                let op = DeriveKey::allocate(
                    AlgorithmId::EcDhDeriveSharedSecret,
                    crypto::ec::curve_to_key_size(curve.into()).0 as usize,
                )
                .map_err(Error::kmerr)?;
                op.set_key(&private_key).map_err(Error::kmerr)?;
                op.derive(
                    &[
                        AttributeMemref::from_ref(AttributeId::EccPublicValueX, peer_x.as_slice())
                            .into(),
                        AttributeMemref::from_ref(AttributeId::EccPublicValueY, peer_y.as_slice())
                            .into(),
                    ],
                    &mut shared,
                );

                let shared =
                    Ec::get_attribute(&shared, AttributeId::SecretValue, secret_size_in_bits / 8)?;
                Ok(shared.0.clone())
            }
            Key::X25519(key) => {
                if spki.algorithm.oid != crypto::ec::X509_X25519_OID {
                    return Err(km_err!(InvalidArgument, "Incompatible peer key"));
                }
                let peer_key: [u8; 32] = spki
                    .subject_public_key
                    .as_bytes()
                    .and_then(|key| key.try_into().ok())
                    .ok_or_else(|| km_err!(InvalidArgument, "Peer public key is invalid"))?;

                // Computed here rather than with TEE_DeriveKey, which panics
                // the TA on an invalid peer key.
                let secret = x25519::StaticSecret::from(key.0);
                let shared = secret.diffie_hellman(&x25519::PublicKey::from(peer_key));
                // A low order peer key gives an all-zero secret, which
                // BoringSSL rejects too.
                if !shared.was_contributory() {
                    return Err(km_err!(InvalidArgument, "Peer public key has a low order"));
                }
                let mut out = vec_try![0u8; shared.as_bytes().len()]?;
                out.copy_from_slice(shared.as_bytes());
                Ok(out)
            }
            _ => Err(km_err!(IncompatibleAlgorithm, "Key not valid for agreement")),
        }
    }
}

struct EcDsaSignOperation {
    key: Key,
    max_size: usize,
    algid: AlgorithmId,
    pending_input: Vec<u8>,
}

// SAFETY: The raw pointer to TEE_OperationHandle is held only by us, so
// it can be safely transferred to another thread.
unsafe impl Send for EcDsaSignOperation {}

impl crypto::AccumulatingOperation for EcDsaSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        // For ECDSA signing, extra data beyond the maximum size is ignored (rather than being
        // rejected via the `max_input_size()` trait method).
        let max_extra_data = self.max_size - self.pending_input.len();
        if max_extra_data > 0 {
            let len = core::cmp::min(max_extra_data, data.len());
            self.pending_input.try_extend_from_slice(&data[..len])?;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let curve = self.key.curve();
        let private_key = Ec::nist_private_key_from_der(
            self.key.private_key_bytes(),
            NistCurve::try_from(curve)?,
            TransientObjectType::EcdsaKeypair,
        )?;

        let cipher = Asymmetric::allocate(
            self.algid,
            OperationMode::Sign,
            crypto::ec::curve_to_key_size(curve).0 as usize,
        )
        .map_err(Error::kmerr)?;
        cipher.set_key(&private_key).map_err(Error::kmerr)?;

        let mut signature = vec_try![0u8; Ec::MAX_SIGNATURE_LEN]?;
        let len = cipher
            .sign_digest(&[], self.pending_input.as_slice(), signature.as_mut_slice())
            .map_err(Error::kmerr)?;
        signature.truncate(len);

        crypto::ec::from_cose_signature(curve, signature.as_slice())
    }
}

struct EcDsaSignDigestOperation {
    key: Key,
    algid: AlgorithmId,
    digest: optee_utee::Digest,
}

// SAFETY: The raw pointer to TEE_OperationHandle is held only by us, so
// it can be safely transferred to another thread.
unsafe impl Send for EcDsaSignDigestOperation {}

impl crypto::AccumulatingOperation for EcDsaSignDigestOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        self.digest.update(data);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let mut digest = vec_try![0u8; Ec::MAX_DIGEST_LEN]?;
        let len = self.digest.do_final(&[], digest.as_mut_slice()).map_err(Error::kmerr)?;
        digest.truncate(len);

        let curve = self.key.curve();
        let private_key = Ec::nist_private_key_from_der(
            self.key.private_key_bytes(),
            NistCurve::try_from(curve)?,
            TransientObjectType::EcdsaKeypair,
        )?;

        let cipher = Asymmetric::allocate(
            self.algid,
            OperationMode::Sign,
            crypto::ec::curve_to_key_size(curve).0 as usize,
        )
        .map_err(Error::kmerr)?;
        cipher.set_key(&private_key).map_err(Error::kmerr)?;

        let mut signature = vec_try![0u8; Ec::MAX_SIGNATURE_LEN]?;
        let len = cipher
            .sign_digest(&[], digest.as_slice(), signature.as_mut_slice())
            .map_err(Error::kmerr)?;
        signature.truncate(len);

        crypto::ec::from_cose_signature(curve, signature.as_slice())
    }
}

struct Ed25519SignOperation {
    key: Key,
    pending_input: Vec<u8>,
}

impl crypto::AccumulatingOperation for Ed25519SignOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(crypto::ec::MAX_ED25519_MSG_SIZE)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), kmr_common::Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, kmr_common::Error> {
        let signing_key = ed25519::SigningKey::from_bytes(
            self.key.private_key_bytes().try_into().map_err(Error::kmerr)?,
        );
        let signature = signing_key
            .try_sign(self.pending_input.as_slice())
            .map_err(|e| km_err!(UnknownError, "Ed25519 signing failed: {:?}", e))?;

        let mut output = vec_try![0u8; ed25519::SIGNATURE_LENGTH]?;
        output.copy_from_slice(&signature.to_bytes());
        Ok(output)
    }
}
