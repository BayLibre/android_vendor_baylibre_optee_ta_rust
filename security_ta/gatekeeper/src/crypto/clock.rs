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

//! Monotonic clock implementation using OP-TEE's TEE_GetSystemTime.

use gk_ta::traits;
use gk_wire::MillisecondsSinceEpoch;

/// Clock implementation backed by OP-TEE's TEE_GetSystemTime.
pub struct Clock;

impl traits::MonotonicClock for Clock {
    fn now(&self) -> MillisecondsSinceEpoch {
        // Secure system time, shared with the KeyMint TA so that it can check
        // HardwareAuthToken timestamps. It restarts at SoC reboot, which
        // gk-ta handles by restarting the throttling timeout.
        MillisecondsSinceEpoch(optee_ta_common::system_time_ms())
    }
}
