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

use optee_ta_common::GATEKEEPER_TA_UUID;
use optee_utee_sys::{TA_FLAG_MULTI_SESSION, TA_FLAG_SINGLE_INSTANCE};

optee_ta_common::ta_config! {
    uuid: GATEKEEPER_TA_UUID,
    // Flags
    //
    // A single instance accepting several sessions, like the KeyMint TA. Only the
    // Gatekeeper HAL opens sessions to this TA; the Gatekeeper TA itself opens a
    // session to the KeyMint TA to get the auth token key.
    //
    // According to GlobalPlatform internal core API spec, section 2.1.3:
    // "Sequential execution of entry points", the TEE-OS core framework guarantees
    // no two TA entry points execute at the same time, even across different sessions.
    //
    // TA_FLAG_USER_MODE and TA_FLAG_EXEC_DDR are not explicitly set here because
    // they are implicit in the OP-TEE Rust TA linker script (user_ta_header.lds),
    // consistent with how the KeyMint Rust TA is built.
    //
    // TA_FLAG_INSTANCE_KEEP_ALIVE is intentionally NOT set here to match the C TA's
    // user_ta_header_defines.h (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR |
    // TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION). Adding KEEP_ALIVE changes
    // TA lifecycle behaviour and must only be added if a specific, tested failure
    // scenario requires it.
    flags: TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION,
    // Memory
    //
    // STACK_SIZE: 64 KB is intentionally larger than the C TA's 16 KB because the
    // Rust no_std runtime and the gk-ta crate require more stack depth for trait
    // dispatch, VecDeque operations, and serialization. Verified to be sufficient
    // under load; reduce only after profiling confirms headroom.
    stack_size: 64 * 1024, // 64 KB (C TA uses 16 KB)

    // HEAP_SIZE: 512 KB is sufficient for the Rust Gatekeeper workload which uses
    // heap-allocated collections (Vec, VecDeque, Box) absent in the C TA. 2 MB was
    // the initial draft value; reduced to conserve TEE secure memory, which is a
    // scarce resource. Increase only if OOM errors are observed under load.
    heap_size: 512 * 1024, // 512 KB (C TA uses 32 KB; Rust needs more)
    description: "Android Gatekeeper TA for OP-TEE",
    trace_prefix: "GK_TA",
}
