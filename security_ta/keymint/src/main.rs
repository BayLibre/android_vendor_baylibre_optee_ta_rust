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

#![no_std]
#![no_main]

#[macro_use]
extern crate alloc;

mod command;
mod config;
mod crypto;
mod error;
mod keys;
mod rpc;
#[path = "../../rust/stubs.rs"]
mod stubs;

use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;
use core::ffi::c_void;
use log::info;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session,
};
use optee_utee::{Error, ErrorKind, ParamType, Parameters, Result};
use spin::Mutex;
use spin::Once;

// SAFETY:
//
// Each OP-TEE TA, per GlobalPlatform internal core API spec v1.1+,
// is essentially a single-threaded environment, in which all TA
// entry points (create, destroy, open_session, close_session, and
// invoke_command) are executed sequentially by the TEE OS.
//
// Thus it is safe to mark the global `kmr_ta::KeyMintTa` variable
// as Send.
//
// We use spin::Once and spin::Mutex for readability rather than
// necessity.
struct SingleThreadedTa(kmr_ta::KeyMintTa);
unsafe impl Send for SingleThreadedTa {}

fn keymint_ta() -> &'static Mutex<SingleThreadedTa> {
    static KEYMINT_TA: Once<Mutex<SingleThreadedTa>> = Once::new();
    KEYMINT_TA.call_once(|| {
        // Allow the HAL to select KeyMint V4 or V5, as done by the Trusty KeyMint TA
        let ta = kmr_ta::KeyMintTa::new_allowing_versions(
            kmr_ta::HardwareInfo {
                version_number: 4,
                security_level: kmr_common::wire::keymint::SecurityLevel::TrustedEnvironment,
                impl_name: "TEE KeyMint in Rust",
                author_name: "BayLibre",
                unique_id: "TEE KeyMint TA",
            },
            kmr_ta::RpcInfo::V3(kmr_ta::RpcInfoV3 {
                author_name: "Google",
                unique_id: "TEE KeyMint TA",
                fused: false,
                supported_num_of_keys_in_csr: kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR,
            }),
            kmr_common::crypto::Implementation {
                rng: Box::new(crypto::rng::Rng),
                clock: Some(Box::new(crypto::clock::Clock)),
                compare: Box::new(crypto::eq::Eq),
                aes: Box::new(crypto::aes::Aes),
                des: Box::new(crypto::des::Des),
                hmac: Box::new(crypto::mac::Hmac),
                rsa: Box::new(crypto::rsa::Rsa),
                ec: Box::new(crypto::ec::Ec),
                ckdf: Box::new(crypto::mac::AesCmac),
                hkdf: Box::new(crypto::mac::Hmac),
                sha256: Box::new(crypto::sha::Sha256),
                // ML-DSA (KeyMint V5) is not supported
                mldsa: Box::new(kmr_common::crypto::NoOpMlDsa),
            },
            kmr_ta::device::Implementation {
                keys: Box::new(keys::Keys),
                sign_info: None,
                attest_ids: None,
                sdd_mgr: None,
                bootloader: Box::new(kmr_ta::device::BootloaderDone),
                sk_wrapper: None,
                tup: Box::new(kmr_ta::device::TrustedPresenceUnsupported),
                legacy_key: None,
                rpc: Box::new(rpc::RpcArtifacts),
            },
            vec![kmr_ta::KeyMintHalVersion::V4, kmr_ta::KeyMintHalVersion::V5],
        );

        Mutex::new(SingleThreadedTa(ta))
    })
}

// The maximum size of an incoming request.
const KEYMINT_MAX_BUFFER_LENGTH: usize = 4096;

// The maximum size of a message's payload. A longer message is split up into
// multiple segments.
const KEYMINT_MAX_MESSAGE_CONTENT_SIZE: usize = 4000;

// The Keymint TA session context.
//
// `ipc_resp` holds the last response of the ta that is to be transferred to the
// client upon request. It is a Vec of Vec because a longer message is broken
// into multiple sub-messages.
//
// `ipc_resp` is only used by command::READ and command::WRITE handlers.
struct SessionContext {
    ipc_resp: Option<VecDeque<Vec<u8>>>,
}

// This default trait is required by ta_* macros that sets up the optional
// session context parameter in ta_open_session, ta_close_session, and
// ta_invoke_command.
impl Default for SessionContext {
    fn default() -> Self {
        info!("Creating SessionContext...");
        Self { ipc_resp: None }
    }
}

#[ta_create]
fn create() -> Result<()> {
    // Log level feature selected by the Makefile from CFG_TEE_TA_LOG_LEVEL
    #[cfg(feature = "log-off")]
    let max_level = log::LevelFilter::Off;
    #[cfg(all(feature = "log-warn", not(any(feature = "log-off", feature = "log-info", feature = "log-debug", feature = "log-trace"))))]
    let max_level = log::LevelFilter::Warn;
    #[cfg(feature = "log-info")]
    let max_level = log::LevelFilter::Info;
    #[cfg(feature = "log-debug")]
    let max_level = log::LevelFilter::Debug;
    #[cfg(feature = "log-trace")]
    let max_level = log::LevelFilter::Trace;

    let config = optee_logger_ta::OpteeLoggerConfig { max_level };
    let _ = optee_logger_ta::init_with_config(config);

    info!("Hello from OP-TEE Keymint in Rust!");

    if !crypto::clock::is_secure_time_source() {
        return Err(Error::new(ErrorKind::Security));
    }

    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut SessionContext) -> Result<()> {
    info!("Keymint TA connected");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut SessionContext) {
    info!("Keymint TA disconnected");
}

#[ta_destroy]
fn destroy() {
    info!("Keymint TA unloading... ");
}

#[ta_invoke_command]
fn invoke_command(
    sess_ctx: &mut SessionContext,
    cmd_id: u32,
    params: &mut Parameters,
) -> Result<()> {
    match cmd_id {
        command::WRITE => handle_ipc_request(sess_ctx, params),
        command::READ => handle_ipc_response(sess_ctx, params),
        _ => Err(Error::new(ErrorKind::NotSupported)),
    }
}

fn handle_ipc_request(keymint_ctx: &mut SessionContext, params: &mut Parameters) -> Result<()> {
    if keymint_ctx.ipc_resp.is_some() {
        // The response of the previous IPC has not been cleared.
        return Err(Error::new(ErrorKind::Busy));
    }

    if params.0.raw().is_null() {
        return Err(Error::new(ErrorKind::BadParameters));
    }
    // SAFETY: as_memref() dereferences the raw TEE_Param pointer, which is non-null.
    let mut p = unsafe { params.0.as_memref()? };

    // Check MemrefInput here because as_memref() does not differentiate
    // between input and output.
    if let ParamType::MemrefInput = p.param_type() {
        let req = p.buffer();
        // Deny requests that are too big.
        if req.len() > KEYMINT_MAX_BUFFER_LENGTH {
            return Err(Error::new(ErrorKind::Overflow));
        }
        let resp = keymint_ta().lock().0.process(req);
        keymint_ctx.ipc_resp = Some(VecDeque::from(
            kmr_ta::split_rsp(resp.as_slice(), KEYMINT_MAX_MESSAGE_CONTENT_SIZE)
                .map_err(|_| Error::new(ErrorKind::Generic))?,
        ));
        Ok(())
    } else {
        Err(Error::new(ErrorKind::BadParameters))
    }
}

fn handle_ipc_response(keymint_ctx: &mut SessionContext, params: &mut Parameters) -> Result<()> {
    // No outstanding response.
    if keymint_ctx.ipc_resp.is_none() {
        return Err(Error::new(ErrorKind::NoData));
    }

    if params.0.raw().is_null() {
        return Err(Error::new(ErrorKind::BadParameters));
    }
    // SAFETY: as_memref() dereferences the raw TEE_Param pointer, which is non-null.
    let mut p = unsafe { params.0.as_memref()? };

    // Check MemrefOutput here because as_memref() does not differentiate
    // between input and output.
    if let ParamType::MemrefOutput = p.param_type() {
        // Take all packets out. Unwrap() never panics.
        let mut packets = keymint_ctx.ipc_resp.take().unwrap();
        // Send only the packet at the front. Unwrap() never panics.
        let packet = packets.pop_front().unwrap();
        if packet.len() > p.buffer().len() {
            return Err(Error::new(ErrorKind::ShortBuffer));
        }
        p.set_updated_size(packet.len());
        p.buffer().copy_from_slice(packet.as_slice());
        if packets.len() > 0 {
            // Put any remaining packets back for the next request.
            keymint_ctx.ipc_resp = Some(packets);
        }
        Ok(())
    } else {
        Err(Error::new(ErrorKind::BadParameters))
    }
}
