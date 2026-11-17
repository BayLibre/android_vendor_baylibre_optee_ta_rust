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

use optee_ta_common::KEYMINT_TA_UUID;
use optee_utee_sys::{TA_FLAG_INSTANCE_KEEP_ALIVE, TA_FLAG_MULTI_SESSION, TA_FLAG_SINGLE_INSTANCE};

optee_ta_common::ta_config! {
    uuid: KEYMINT_TA_UUID,
    // Flags
    // Configure the KeyMint TA to accept multiple sessions from a single instance,
    // so that clients other than the KeyMint HAL (e.g. the Gatekeeper TA) can
    // communicate with the KeyMint TA over a separate session.
    // TA_FLAG_INSTANCE_KEEP_ALIVE keeps the instance loaded when its last session
    // closes, e.g. when the HAL restarts. Otherwise the in-memory state of the TA
    // (boot info, ISharedSecret key, DICE artefacts) would be lost.
    flags: TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_INSTANCE_KEEP_ALIVE,
    // Memory
    stack_size: 128 * 1024, // 128 KB
    heap_size: 3 * 1024 * 1024, // 3 MB
    description: "Android Keymint TA for OP-TEE",
    trace_prefix: "KM_TA",
}
