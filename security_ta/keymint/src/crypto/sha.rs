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
use kmr_common::crypto;
use optee_utee::{AlgorithmId, Digest};

pub struct Sha256;

impl crypto::Sha256 for Sha256 {
    fn hash(&self, data: &[u8]) -> Result<[u8; 32], kmr_common::Error> {
        let mut hash: [u8; 32] = [0; 32];
        let op = Digest::allocate(AlgorithmId::Sha256).map_err(Error::kmerr)?;
        op.do_final(data, &mut hash).map_err(Error::kmerr)?;
        Ok(hash)
    }
}
