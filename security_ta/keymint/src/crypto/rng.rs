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

use kmr_common::crypto;
use optee_utee::Random;

pub struct Rng;

impl crypto::Rng for Rng {
    fn add_entropy(&mut self, data: &[u8]) {
        if !data.is_empty() {
            let _ = optee_ipc_ta::add_rng_entropy(data);
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::generate(dest);
    }
}
