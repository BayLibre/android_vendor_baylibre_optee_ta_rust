//
// Copyright (C) 2026 BayLibre
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

//! Code shared by the KeyMint and Gatekeeper TAs.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use log::error;
use optee_utee::{Error, ErrorKind, ParamType, Parameter, Result};
use optee_utee_sys::TEE_UUID;

// Used by ta_config!, so that the TAs do not need to import its types.
#[doc(hidden)]
pub use optee_utee_sys as __sys;

/// dba51a17-0563-11e7-93b1-6fa7b0071a51, must match
/// security_ta/keymint/{Makefile,Android.mk}.
pub const KEYMINT_TA_UUID: TEE_UUID = TEE_UUID {
    timeLow: 0xdba51a17,
    timeMid: 0x0563,
    timeHiAndVersion: 0x11e7,
    clockSeqAndNode: [0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51],
};

/// 4d573443-6a56-4272-ac6f-2425af9ef9bb, must match
/// security_ta/gatekeeper/{Makefile,Android.mk}.
pub const GATEKEEPER_TA_UUID: TEE_UUID = TEE_UUID {
    timeLow: 0x4d573443,
    timeMid: 0x6a56,
    timeHiAndVersion: 0x4272,
    clockSeqAndNode: [0xac, 0x6f, 0x24, 0x25, 0xaf, 0x9e, 0xf9, 0xbb],
};

/// TEE system time in milliseconds. TEE Internal Core API Specification
/// 7.2.1: "the system time SHALL be monotonic for a given TA instance."
pub fn system_time_ms() -> i64 {
    let mut time = optee_utee_sys::TEE_Time { seconds: 0, millis: 0 };
    // SAFETY: time is a valid reference.
    unsafe { optee_utee_sys::TEE_GetSystemTime(&mut time) };
    time.seconds as i64 * 1000 + time.millis as i64
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

/// Return a copy of the buffer of `param`, which must be a MEMREF_INPUT of at
/// most `max_len` bytes.
pub fn read_input(param: &mut Parameter, max_len: usize) -> Result<Vec<u8>> {
    if param.raw().is_null() || !matches!(param.param_type, ParamType::MemrefInput) {
        return Err(Error::new(ErrorKind::BadParameters));
    }
    // SAFETY: OP-TEE passes a valid TEE_Param, non-null, for a memref parameter.
    let mut p = unsafe { param.as_memref()? };
    // SAFETY: p.raw() points into the TEE_Param checked above. An empty
    // memref can have a null buffer, which buffer() does not accept.
    if unsafe { (*p.raw()).size } == 0 {
        return Ok(Vec::new());
    }
    if p.buffer().len() > max_len {
        return Err(Error::new(ErrorKind::Overflow));
    }
    Ok(p.buffer().to_vec())
}

/// Check that `param` is a MEMREF_OUTPUT of at least `min_len` bytes, before
/// doing work whose result would be lost otherwise.
pub fn check_output(param: &mut Parameter, min_len: usize) -> Result<()> {
    if param.raw().is_null() || !matches!(param.param_type, ParamType::MemrefOutput) {
        return Err(Error::new(ErrorKind::BadParameters));
    }
    // SAFETY: as in read_input().
    if unsafe { (*param.as_memref()?.raw()).size } < min_len {
        return Err(Error::new(ErrorKind::ShortBuffer));
    }
    Ok(())
}

/// Copy `data` to `param`, a MEMREF_OUTPUT, and set its size.
pub fn write_output(param: &mut Parameter, data: &[u8]) -> Result<()> {
    check_output(param, 0)?;
    // SAFETY: OP-TEE passes a valid TEE_Param, non-null, for a memref parameter.
    let mut p = unsafe { param.as_memref()? };
    // SAFETY: as in read_input().
    if unsafe { (*p.raw()).size } == 0 {
        if !data.is_empty() {
            return Err(Error::new(ErrorKind::ShortBuffer));
        }
        return Ok(());
    }
    if data.len() > p.buffer().len() {
        return Err(Error::new(ErrorKind::ShortBuffer));
    }
    p.buffer()[..data.len()].copy_from_slice(data);
    p.set_updated_size(data.len());
    Ok(())
}

/// Defines the symbols that OP-TEE expects in a TA: its header (`ta_head`),
/// its properties (`ta_props`), its heap and its trace settings.
///
/// They must be defined in the TA crate itself, so this is a macro, to be
/// called once, from the TA `config.rs`.
#[macro_export]
macro_rules! ta_config {
    (
        uuid: $uuid:expr,
        flags: $flags:expr,
        stack_size: $stack_size:expr,
        heap_size: $heap_size:expr,
        description: $description:literal,
        trace_prefix: $trace_prefix:literal $(,)?
    ) => {
        const FLAGS: u32 = $flags;
        const STACK_SIZE: u32 = $stack_size;
        const HEAP_SIZE: usize = $heap_size;

        // Heap
        #[no_mangle]
        pub static ta_heap_size: usize = HEAP_SIZE;
        #[no_mangle]
        #[link_section = ".bss"]
        pub static ta_heap: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

        // Header
        #[no_mangle]
        #[link_section = ".ta_head"]
        pub static ta_head: $crate::__sys::ta_head = $crate::__sys::ta_head {
            uuid: $uuid,
            stack_size: STACK_SIZE,
            flags: FLAGS,
            depr_entry: u64::MAX,
        };

        // Properties
        #[no_mangle]
        pub static ta_props: [$crate::__sys::user_ta_property; 8] = [
            // Flags
            $crate::__sys::user_ta_property {
                name: $crate::__sys::TA_PROP_STR_SINGLE_INSTANCE,
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_BOOL,
                value: &(FLAGS & $crate::__sys::TA_FLAG_SINGLE_INSTANCE != 0) as *const bool
                    as _,
            },
            $crate::__sys::user_ta_property {
                name: $crate::__sys::TA_PROP_STR_MULTI_SESSION,
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_BOOL,
                value: &(FLAGS & $crate::__sys::TA_FLAG_MULTI_SESSION != 0) as *const bool as _,
            },
            // Memory
            $crate::__sys::user_ta_property {
                name: $crate::__sys::TA_PROP_STR_DATA_SIZE,
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_U32,
                value: &(HEAP_SIZE as u32) as *const u32 as *mut _,
            },
            $crate::__sys::user_ta_property {
                name: $crate::__sys::TA_PROP_STR_STACK_SIZE,
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_U32,
                value: &STACK_SIZE as *const u32 as *mut _,
            },
            // Description
            $crate::__sys::user_ta_property {
                name: $crate::__sys::TA_PROP_STR_DESCRIPTION,
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_STRING,
                value: concat!("This is the ", $description, ".\0").as_ptr() as _,
            },
            $crate::__sys::user_ta_property {
                name: "gp.ta.description\0".as_ptr(),
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_STRING,
                value: concat!($description, "\0").as_ptr() as _,
            },
            // Version
            $crate::__sys::user_ta_property {
                name: $crate::__sys::TA_PROP_STR_VERSION,
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_STRING,
                value: b"0.1\0".as_ptr() as _,
            },
            $crate::__sys::user_ta_property {
                name: "gp.ta.version\0".as_ptr(),
                prop_type: $crate::__sys::user_ta_prop_type::USER_TA_PROP_TYPE_U32,
                value: &0x0010u32 as *const u32 as *mut _,
            },
        ];
        #[no_mangle]
        pub static ta_num_props: usize = ta_props.len();

        // Tracing
        #[no_mangle]
        pub static trace_ext_prefix: &[u8] = concat!($trace_prefix, "\0").as_bytes();
        #[no_mangle]
        pub static mut trace_level: core::ffi::c_int = 4;
        #[no_mangle]
        pub unsafe extern "C" fn tahead_get_trace_level() -> core::ffi::c_int {
            return trace_level;
        }
    };
}
