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
mod invoke;
mod storage;
#[path = "../../common/stubs.rs"]
mod stubs;

use alloc::boxed::Box;
use core::ffi::c_void;
use gk_ta::traits::Implementation;
use gk_ta::GatekeeperTa;
use gk_wire::{ApiStatus, PerformOpReq, PerformOpResponse};
use hal_wire::AsCborValue;
use log::{info, warn};
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use spin::Mutex;
use spin::Once;

// SAFETY:
//
// Each OP-TEE TA, per GlobalPlatform internal core API spec v1.1+,
// is essentially a single-threaded environment in which all TA
// entry points (create, destroy, open_session, close_session, and
// invoke_command) are executed sequentially by the TEE OS.
//
// Thus it is safe to mark the global `GatekeeperTa` variable as Send.
//
// We use spin::Once and spin::Mutex for readability rather than necessity.
struct SingleThreadedTa(GatekeeperTa);
unsafe impl Send for SingleThreadedTa {}

fn gatekeeper_ta() -> &'static Mutex<SingleThreadedTa> {
    static GATEKEEPER_TA: Once<Mutex<SingleThreadedTa>> = Once::new();
    GATEKEEPER_TA.call_once(|| {
        // Two independent HMAC instances: one for general signing, one for auth token key
        // management (AuthKey uses it internally to sign tokens with the KeyMint key).
        let hmac_impl: Box<dyn gk_ta::traits::HmacSha256> = Box::new(crypto::hmac::HmacSha256);
        let hmac_for_auth: Box<dyn gk_ta::traits::HmacSha256> = Box::new(crypto::hmac::HmacSha256);

        // AuthKey fetches the ISharedSecret-agreed key from KeyMint at each sign() call.
        let auth_key: Box<dyn gk_ta::traits::AuthKeyManagement> =
            Box::new(crypto::authkey::AuthKey::new(hmac_for_auth));

        let imp = Implementation {
            rng: Box::new(crypto::rng::Rng),
            clock: Box::new(crypto::clock::Clock),
            compare: Box::new(crypto::eq::Eq),
            hmac: hmac_impl,
            password: Box::new(crypto::password::PasswordKey),
            auth_key,
            failures: Box::new(storage::SecureStorage),
            shared_secret: None,
        };

        let ta = GatekeeperTa::new(imp);
        Mutex::new(SingleThreadedTa(ta))
    })
}

// Maximum incoming serialized request size.  Must match
// SerializedChannel::MAX_SIZE in hardware/baylibre/optee_hal_rust/gatekeeper/src/
// gatekeeper_hal_main.rs so the TA and HAL agree on
// the largest payload either side will accept.
const GK_MAX_BUFFER_LENGTH: usize = 8000;

// Maximum size of a response. Must match GK_RESPONSE_MAX in
// optee_channel/optee_channel.rs.
const GK_MAX_MESSAGE_CONTENT_SIZE: usize = 4096;

// No per-session state is required: GatekeeperTa is a global singleton and
// each PROCESS command is fully self-contained.
#[derive(Default)]
struct SessionContext;

#[ta_create]
fn create() -> Result<()> {
    // Log level feature selected by the Makefile from CFG_TEE_TA_LOG_LEVEL
    #[cfg(feature = "log-off")]
    let max_level = log::LevelFilter::Off;
    #[cfg(all(
        feature = "log-warn",
        not(any(
            feature = "log-off",
            feature = "log-info",
            feature = "log-debug",
            feature = "log-trace"
        ))
    ))]
    let max_level = log::LevelFilter::Warn;
    #[cfg(feature = "log-info")]
    let max_level = log::LevelFilter::Info;
    #[cfg(feature = "log-debug")]
    let max_level = log::LevelFilter::Debug;
    #[cfg(feature = "log-trace")]
    let max_level = log::LevelFilter::Trace;

    let config = optee_logger_ta::OpteeLoggerConfig { max_level };
    let _ = optee_logger_ta::init_with_config(config);

    info!("Hello from OP-TEE Gatekeeper in Rust!");

    if !optee_ta_common::is_secure_time_source() {
        return Err(Error::new(ErrorKind::Security));
    }

    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut SessionContext) -> Result<()> {
    info!("Gatekeeper TA connected");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut SessionContext) {
    info!("Gatekeeper TA disconnected");
}

#[ta_destroy]
fn destroy() {
    info!("Gatekeeper TA unloading...");
}

#[ta_invoke_command]
fn invoke_command(
    _sess_ctx: &mut SessionContext,
    cmd_id: u32,
    params: &mut Parameters,
) -> Result<()> {
    match cmd_id {
        command::PROCESS => handle_gk_request(params),
        _ => Err(Error::new(ErrorKind::NotSupported)),
    }
}

/// gk-ta counts a verify as a failure before checking the password, and clears
/// the count only after signing the auth token. Reject verify requests while
/// KeyMint has no auth token key, so that a correct password is not recorded as
/// a failure.
fn is_verify_without_auth_key(req_data: &[u8]) -> bool {
    if !matches!(PerformOpReq::from_slice(req_data), Ok(PerformOpReq::Verify(_))) {
        return false;
    }
    if invoke::get_keymint_auth_token_key().is_ok() {
        return false;
    }
    warn!("No auth token key from KeyMint, rejecting verify");
    true
}

fn handle_gk_request(params: &mut Parameters) -> Result<()> {
    // Serialized request in param[0] (MEMREF_INPUT).
    let req_data = optee_ta_common::read_input(&mut params.0, GK_MAX_BUFFER_LENGTH)?;

    // Check param[1] (MEMREF_OUTPUT) and its size before processing: a verify
    // updates the failure record, which must not happen without a response.
    optee_ta_common::check_output(&mut params.1, GK_MAX_MESSAGE_CONTENT_SIZE)?;

    let resp = if is_verify_without_auth_key(&req_data) {
        PerformOpResponse::Err(ApiStatus::GeneralFailure as i32)
            .into_vec()
            .map_err(|_| Error::new(ErrorKind::Generic))?
    } else {
        gatekeeper_ta().lock().0.process(&req_data)
    };

    // Serialized response in param[1].
    optee_ta_common::write_output(&mut params.1, &resp)
}
