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
use log::error;
use optee_utee_sys;

pub struct Clock;

impl crypto::MonotonicClock for Clock {
    fn now(&self) -> crypto::MillisecondsSinceEpoch {
        let mut time = optee_utee_sys::TEE_Time { seconds: 0, millis: 0 };

        // TEE Internal Core API Specification 7.2.1: "the system time
        // SHALL be monotonic for a given TA instance."
        // SAFETY: time is a valid reference.
        unsafe {
            optee_utee_sys::TEE_GetSystemTime(&mut time);
        }

        let ms = time.seconds as i64 * 1000 + time.millis as i64;
        crypto::MillisecondsSinceEpoch(ms)
    }
}

/// Return true if the REE cannot change the TEE system time, i.e. if
/// `gpd.tee.systemTime.protectionLevel` is at least 1000 (GP TEE Internal Core API).
pub fn is_secure_time_source() -> bool {
    let mut level: u32 = 0;

    // SAFETY: the name is NUL-terminated and level is a valid reference.
    let res = unsafe {
        optee_utee_sys::TEE_GetPropertyAsU32(
            optee_utee_sys::TEE_PROPSET_TEE_IMPLEMENTATION,
            b"gpd.tee.systemTime.protectionLevel\0".as_ptr() as *const core::ffi::c_char,
            &mut level,
        )
    };

    if res != optee_utee_sys::TEE_SUCCESS {
        error!("Cannot read the system time protection level: {:#x}", res);
        return false;
    }
    if level < 1000 {
        error!("Insecure system time source: protection level {}", level);
        return false;
    }
    true
}
