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

//! Random number generation using OP-TEE's TEE_GenerateRandom.

use gk_ta::traits;
use optee_utee::Random;

/// RNG implementation backed by OP-TEE's hardware random number generator.
pub struct Rng;

impl traits::Rng for Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::generate(dest);
    }
}
