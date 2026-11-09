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

use kmr_wire::keymint::Digest;
use optee_utee::AlgorithmId;

pub mod aes;
pub mod clock;
pub mod des;
pub mod ec;
pub mod eq;
pub mod mac;
pub mod nist_point;
pub mod operation;
pub mod rng;
pub mod rsa;
pub mod sha;

fn digest_to_algid(digest: Digest) -> Option<AlgorithmId> {
    match digest {
        Digest::None => None,
        Digest::Md5 => Some(AlgorithmId::Md5),
        Digest::Sha1 => Some(AlgorithmId::Sha1),
        Digest::Sha224 => Some(AlgorithmId::Sha224),
        Digest::Sha256 => Some(AlgorithmId::Sha256),
        Digest::Sha384 => Some(AlgorithmId::Sha384),
        Digest::Sha512 => Some(AlgorithmId::Sha512),
    }
}
