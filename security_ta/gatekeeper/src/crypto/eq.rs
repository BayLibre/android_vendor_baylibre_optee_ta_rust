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

//! Constant-time equality comparison using OP-TEE's TEE_MemCompare.

use core::ffi::c_void;
use gk_ta::traits;
use optee_utee_sys;

/// Constant-time equality implementation backed by OP-TEE's TEE_MemCompare.
pub struct Eq;

impl traits::ConstTimeEq for Eq {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }

        if left.is_empty() {
            return true;
        }

        // OP-TEE implementation of TEE_MemCompare uses consttime_memcmp,
        // which is constant-time.
        // SAFETY: both buffers are valid and equal length.
        let res = unsafe {
            optee_utee_sys::TEE_MemCompare(
                left.as_ptr() as *const c_void,
                right.as_ptr() as *const c_void,
                left.len(),
            )
        };

        res == 0
    }
}
