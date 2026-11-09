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

//! Shared OP-TEE IPC channel for HAL services.
//!
//! [`OpteeChannel::execute_single`]: single TEEC_InvokeCommand with
//! param[0]=MEMREF_TEMP_INPUT (request) and param[1]=MEMREF_TEMP_OUTPUT (response).
//! Used by the Gatekeeper Rust TA whose responses are small and bounded.

use tee_optee_bindings::{
    param_types, uuid_from_str,
    TEEC_Context, TEEC_Session, TEEC_Operation,
    TEEC_SUCCESS, TEEC_ERROR_TARGET_DEAD,
    TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
    TEEC_InitializeContext, TEEC_FinalizeContext,
    TEEC_OpenSession, TEEC_CloseSession, TEEC_InvokeCommand,
};
use log::debug;
use std::mem::MaybeUninit;

const CMD_PROCESS: u32 = 1026;

/// Response buffer size for execute_single
const GK_RESPONSE_MAX: usize = 4096;

/// OP-TEE IPC channel shared between HAL services.
///
/// The context is heap-allocated so that its address is stable after construction
#[derive(Debug)]
pub struct OpteeChannel {
    context: Box<TEEC_Context>,
    session: TEEC_Session,
}

unsafe impl Send for OpteeChannel {}

impl OpteeChannel {
    /// Open a new OP-TEE context and session to the TA identified by `ta_uuid`.
    pub fn new(ta_uuid: &str) -> Result<Self, String> {
        let (context, session) = Self::open_session(ta_uuid)?;
        Ok(Self { context, session })
    }

    /// Open a fresh OP-TEE context + session.
    fn open_session(ta_uuid: &str) -> Result<(Box<TEEC_Context>, TEEC_Session), String> {
        let uuid = uuid_from_str(ta_uuid).ok_or_else(|| "Invalid TA UUID".to_string())?;

        unsafe {
            let mut context_uninit = MaybeUninit::uninit();
            let result = TEEC_InitializeContext(std::ptr::null(), context_uninit.as_mut_ptr());
            if result != TEEC_SUCCESS {
                return Err(format!("TEEC_InitializeContext failed: 0x{:08x}", result));
            }
            let mut context = Box::new(context_uninit.assume_init());

            let mut session = MaybeUninit::uninit();
            let mut return_origin = 0u32;
            let result = TEEC_OpenSession(
                context.as_mut(),
                session.as_mut_ptr(),
                &uuid,
                0, // TEEC_LOGIN_PUBLIC
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut return_origin,
            );

            if result != TEEC_SUCCESS {
                TEEC_FinalizeContext(context.as_mut());
                return Err(format!(
                    "TEEC_OpenSession failed: 0x{:08x} (origin: {})",
                    result, return_origin
                ));
            }

            Ok((context, session.assume_init()))
        }
    }

    /// Send `req` to the TA using a single TEEC_InvokeCommand and return the response.
    pub fn execute_single(&mut self, req: &[u8]) -> Result<Vec<u8>, String> {
        unsafe {
            let mut return_origin = 0u32;
            let mut resp_buf = vec![0u8; GK_RESPONSE_MAX];

            let mut op: TEEC_Operation = std::mem::zeroed();
            op.paramTypes = param_types(
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_MEMREF_TEMP_OUTPUT,
                TEEC_NONE, TEEC_NONE,
            );
            op.params[0].tmpref.buffer = req.as_ptr() as *mut _;
            op.params[0].tmpref.size = req.len();
            op.params[1].tmpref.buffer = resp_buf.as_mut_ptr() as *mut _;
            op.params[1].tmpref.size = resp_buf.len();

            let result = TEEC_InvokeCommand(
                &mut self.session,
                CMD_PROCESS,
                &mut op,
                &mut return_origin,
            );

            if result == TEEC_ERROR_TARGET_DEAD {
                return Err(format!(
                    "CMD_PROCESS: TA dead (origin: {}), a reboot is required", return_origin
                ));
            }
            if result != TEEC_SUCCESS {
                return Err(format!(
                    "TEEC_InvokeCommand failed: 0x{:08x} (origin: {})", result, return_origin
                ));
            }

            let resp_size = op.params[1].tmpref.size;
            if resp_size > resp_buf.len() {
                return Err(format!(
                    "Response truncated: TA needed {} bytes, buffer is {} bytes",
                    resp_size, resp_buf.len()
                ));
            }
            resp_buf.truncate(resp_size);
            debug!("execute_single: {} bytes response", resp_size);
            Ok(resp_buf)
        }
    }
}

impl Drop for OpteeChannel {
    fn drop(&mut self) {
        debug!("OpteeChannel::drop() - Closing OP-TEE session and context");
        unsafe {
            TEEC_CloseSession(&mut self.session);
            TEEC_FinalizeContext(self.context.as_mut());
        }
        debug!("OpteeChannel::drop() - Session and context closed");
    }
}
