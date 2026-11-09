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

use core::ffi::c_void;
use kmr_common::crypto;
use optee_utee_sys;

pub struct Eq;

impl crypto::ConstTimeEq for Eq {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }

        // OP-TEE implementation of TEE_MemCompare uses consttime_memcmp,
        // which is constant-time.
        // SAFETY: both buffers are valid and equal length.
        let res = unsafe {
            optee_utee_sys::TEE_MemCompare(
                left.as_ptr() as *const c_void,
                right.as_ptr() as *const c_void,
                left.len() as usize,
            )
        };

        res == 0
    }
}
