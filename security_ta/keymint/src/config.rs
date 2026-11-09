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

use core::ffi::c_int;
use core::primitive::u64;
use optee_utee_sys::user_ta_prop_type::{
    USER_TA_PROP_TYPE_BOOL, USER_TA_PROP_TYPE_STRING, USER_TA_PROP_TYPE_U32,
};
use optee_utee_sys::{
    ta_head, user_ta_property, TA_FLAG_INSTANCE_KEEP_ALIVE, TA_FLAG_MULTI_SESSION, TA_FLAG_SINGLE_INSTANCE,
    TA_PROP_STR_DATA_SIZE, TA_PROP_STR_DESCRIPTION, TA_PROP_STR_MULTI_SESSION,
    TA_PROP_STR_SINGLE_INSTANCE, TA_PROP_STR_STACK_SIZE, TA_PROP_STR_VERSION, TEE_UUID,
};

// UUID, must match the Makefile: dba51a17-0563-11e7-93b1-6fa7b0071a51
const UUID: TEE_UUID = TEE_UUID {
    timeLow: 0xdba51a17,
    timeMid: 0x0563,
    timeHiAndVersion: 0x11e7,
    clockSeqAndNode: [0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51],
};

// Flags
//
// Configure the KeyMint TA to accept multiple sessions from a single instance,
// so that clients other than the KeyMint HAL (e.g. the Gatekeeper TA) can
// communicate with the KeyMint TA over a separate session.
//
// According to GlobalPlatform internal core API spec, section 2.1.3:
// "Sequential execution of entry points", the TEE-OS core framework guarantees
// no two TA entry points (including command invocation entry points) execute
// at the same time, even when commands are associated with different sessions.
//
// TA_FLAG_INSTANCE_KEEP_ALIVE keeps the instance loaded when its last session
// closes, e.g. when the HAL restarts. Otherwise the in-memory state of the TA
// (boot info, ISharedSecret key, DICE artefacts) would be lost.
const FLAGS: u32 = TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_INSTANCE_KEEP_ALIVE;

// Memory
const STACK_SIZE: u32 = 128 * 1024; // 128 KB
const HEAP_SIZE: usize = 3 * 1024 * 1024; // 3 MB

// Heap
#[no_mangle]
pub static ta_heap_size: usize = HEAP_SIZE;
#[no_mangle]
#[link_section = ".bss"]
pub static ta_heap: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

// Header
#[no_mangle]
#[link_section = ".ta_head"]
pub static ta_head: ta_head =
    ta_head { uuid: UUID, stack_size: STACK_SIZE, flags: FLAGS, depr_entry: u64::MAX };

// Properties
#[no_mangle]
pub static ta_props: [user_ta_property; 8] = [
    // Flags
    user_ta_property {
        name: TA_PROP_STR_SINGLE_INSTANCE,
        prop_type: USER_TA_PROP_TYPE_BOOL,
        value: &(FLAGS & TA_FLAG_SINGLE_INSTANCE != 0) as *const bool as _,
    },
    user_ta_property {
        name: TA_PROP_STR_MULTI_SESSION,
        prop_type: USER_TA_PROP_TYPE_BOOL,
        value: &(FLAGS & TA_FLAG_MULTI_SESSION != 0) as *const bool as _,
    },
    // Memory
    user_ta_property {
        name: TA_PROP_STR_DATA_SIZE,
        prop_type: USER_TA_PROP_TYPE_U32,
        value: &(HEAP_SIZE as u32) as *const u32 as *mut _,
    },
    user_ta_property {
        name: TA_PROP_STR_STACK_SIZE,
        prop_type: USER_TA_PROP_TYPE_U32,
        value: &STACK_SIZE as *const u32 as *mut _,
    },
    // Description
    user_ta_property {
        name: TA_PROP_STR_DESCRIPTION,
        prop_type: USER_TA_PROP_TYPE_STRING,
        value: b"This is the Android Keymint TA for OP-TEE.\0".as_ptr() as _,
    },
    user_ta_property {
        name: "gp.ta.description\0".as_ptr(),
        prop_type: USER_TA_PROP_TYPE_STRING,
        value: b"Android Keymint TA for OP-TEE\0".as_ptr() as _,
    },
    // Version
    user_ta_property {
        name: TA_PROP_STR_VERSION,
        prop_type: USER_TA_PROP_TYPE_STRING,
        value: b"0.1\0".as_ptr() as _,
    },
    user_ta_property {
        name: "gp.ta.version\0".as_ptr(),
        prop_type: USER_TA_PROP_TYPE_U32,
        value: &0x0010u32 as *const u32 as *mut _,
    },
];
#[no_mangle]
pub static ta_num_props: usize = ta_props.len();

// Tracing
#[no_mangle]
pub static trace_ext_prefix: &[u8] = b"KM_TA\0";
#[no_mangle]
pub static mut trace_level: c_int = 4;
#[no_mangle]
pub unsafe extern "C" fn tahead_get_trace_level() -> c_int {
    return trace_level;
}
