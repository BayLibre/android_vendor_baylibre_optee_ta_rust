//
// Copyright (C) 2026 BayLibre
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Shared OP-TEE TA-to-TA and TA-to-PTA IPC primitives.
//!
//! Provides the `Param`/`Params`/`Session` types and the `open()` entry point
//! that wrap the raw `TEE_OpenTASession` / `TEE_InvokeTACommand` /
//! `TEE_CloseTASession` syscalls.  Error values are returned as
//! `optee_utee::Error`; callers map them to their own domain error type.

#![no_std]

use core::marker::PhantomData;
use core::ptr;
use optee_utee::{Error, ParamType, Uuid};
use optee_utee_sys::{
    Memref, TEE_CloseTASession, TEE_InvokeTACommand, TEE_OpenTASession, TEE_Param,
    TEE_TASessionHandle, Value, TEE_SUCCESS, TEE_TIMEOUT_INFINITE,
};

// OP-TEE system PTA (optee_os/lib/libutee/include/pta_system.h)
pub const PTA_SYSTEM_UUID: &str = "3a2f8978-5dc0-11e8-9c2d-fa7ae01bbebc";
pub const PTA_SYSTEM_ADD_RNG_ENTROPY: u32 = 0;
pub const PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY: u32 = 1;

pub enum Direction {
    In,
    Out,
    Both,
}

pub struct Param<'a> {
    pub(crate) raw: TEE_Param,
    pub(crate) param_type: ParamType,
    phantom: PhantomData<&'a mut i32>,
}

impl<'a> Param<'a> {
    pub fn empty() -> Params<'a> {
        Params(Self::none(), Self::none(), Self::none(), Self::none())
    }

    pub fn none() -> Self {
        Self {
            raw: TEE_Param { value: Value { a: 0, b: 0 } },
            param_type: ParamType::None,
            phantom: PhantomData,
        }
    }

    pub fn from_slice(data: &'a [u8]) -> Self {
        Self {
            raw: TEE_Param {
                memref: Memref { buffer: data.as_ptr() as _, size: data.len() },
            },
            param_type: ParamType::MemrefInput,
            phantom: PhantomData,
        }
    }

    pub fn from_mut_slice(data: &'a mut [u8], direction: Direction) -> Self {
        Self {
            raw: TEE_Param {
                memref: Memref { buffer: data.as_mut_ptr() as _, size: data.len() },
            },
            param_type: match direction {
                Direction::In => ParamType::MemrefInput,
                Direction::Out => ParamType::MemrefOutput,
                Direction::Both => ParamType::MemrefInout,
            },
            phantom: PhantomData,
        }
    }

    pub fn from_value(a: u32, b: u32, direction: Direction) -> Self {
        Self {
            raw: TEE_Param { value: Value { a, b } },
            param_type: match direction {
                Direction::In => ParamType::ValueInput,
                Direction::Out => ParamType::ValueOutput,
                Direction::Both => ParamType::ValueInout,
            },
            phantom: PhantomData,
        }
    }
}

pub struct Params<'a>(pub Param<'a>, pub Param<'a>, pub Param<'a>, pub Param<'a>);

fn param_types(params: &Params) -> u32 {
    (params.0.param_type as u32 & 0xf)
        | ((params.1.param_type as u32 & 0xf) << 4)
        | ((params.2.param_type as u32 & 0xf) << 8)
        | ((params.3.param_type as u32 & 0xf) << 12)
}

/// Open a session to a TA or PTA identified by `uuid`.
///
/// # Safety
/// Pointers embedded in `params` must remain valid for the duration of the call.
pub fn open(uuid: &Uuid, params: &Params) -> Result<Session, Error> {
    let mut raw_handle: TEE_TASessionHandle = ptr::null_mut();
    let types = param_types(params);
    let mut parambuf: [TEE_Param; 4] =
        [params.0.raw, params.1.raw, params.2.raw, params.3.raw];
    let mut origin: u32 = 0;

    // SAFETY: pointers are valid during the function call.
    match unsafe {
        TEE_OpenTASession(
            uuid.as_raw_ptr(),
            TEE_TIMEOUT_INFINITE,
            types,
            parambuf.as_mut_ptr() as _,
            &mut raw_handle as _,
            &mut origin,
        )
    } {
        TEE_SUCCESS => Ok(Session { handle: raw_handle, origin }),
        code => Err(Error::from_raw_error(code)),
    }
}

pub struct Session {
    handle: TEE_TASessionHandle,
    #[allow(dead_code)]
    pub origin: u32,
}

impl Session {
    /// The callee works on a copy of `params`: the sizes it updates in output
    /// memrefs are not returned, so the outputs must have a fixed size.
    pub fn invoke(&self, command: u32, params: &Params) -> Result<u32, Error> {
        let types = param_types(params);
        let mut parambuf: [TEE_Param; 4] =
            [params.0.raw, params.1.raw, params.2.raw, params.3.raw];
        let mut origin: u32 = 0;

        // SAFETY: pointers are valid during the function call.
        match unsafe {
            TEE_InvokeTACommand(
                self.handle,
                TEE_TIMEOUT_INFINITE,
                command,
                types,
                parambuf.as_mut_ptr() as _,
                &mut origin,
            )
        } {
            TEE_SUCCESS => Ok(origin),
            code => Err(Error::from_raw_error(code)),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: self.handle was initialised in open() and is non-null.
            unsafe { TEE_CloseTASession(self.handle) }
        }
    }
}

fn open_system_pta(params: &Params) -> Result<Session, Error> {
    open(&Uuid::parse_str(PTA_SYSTEM_UUID)?, params)
}

/// Derive a key bound to the device and to the calling TA, of `key.len()`
/// bytes (16 to 32), from `input` (system PTA, PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY).
pub fn derive_ta_unique_key(input: &[u8], key: &mut [u8]) -> Result<(), Error> {
    let mut params = Param::empty();
    let session = open_system_pta(&params)?;
    params.0 = Param::from_slice(input);
    params.1 = Param::from_mut_slice(key, Direction::Out);
    session.invoke(PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY, &params)?;
    Ok(())
}

/// Add `data` to the OP-TEE entropy pool (system PTA, PTA_SYSTEM_ADD_RNG_ENTROPY).
pub fn add_rng_entropy(data: &[u8]) -> Result<(), Error> {
    let mut params = Param::empty();
    let session = open_system_pta(&params)?;
    params.0 = Param::from_slice(data);
    session.invoke(PTA_SYSTEM_ADD_RNG_ENTROPY, &params)?;
    Ok(())
}
