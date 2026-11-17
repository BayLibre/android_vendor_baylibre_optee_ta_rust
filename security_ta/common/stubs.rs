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

// https://github.com/rust-lang/rust/issues/106864

#[no_mangle]
extern "C" fn rust_eh_personality() {}

#[allow(non_snake_case)]
#[no_mangle]
extern "C" fn _Unwind_Resume() {}

// getauxval() - may be required by Rust's compiler-builtins for CPU feature
// detection. Report no optional feature: OP-TEE doesn't emulate the ID
// register reads at S-EL0, so the TA can't detect them.
#[no_mangle]
pub extern "C" fn getauxval(_type: core::ffi::c_ulong) -> core::ffi::c_ulong {
    0
}

// bcmp() - required by Rust's core library for slice comparison.
// Pure Rust implementation to avoid OP-TEE memcmp ABI issues with size_t.
#[no_mangle]
pub unsafe extern "C" fn bcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    for i in 0..n {
        if *s1.add(i) != *s2.add(i) {
            return 1;
        }
    }
    0
}
