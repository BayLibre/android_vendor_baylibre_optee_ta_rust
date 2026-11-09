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

extern crate alloc;

mod command;
mod config;
#[path = "../../common/stubs.rs"]
mod stubs;

use alloc::boxed::Box;
use core::ffi::c_void;
use gk_wire::{ApiStatus, PerformOpResponse};
use hal_wire::AsCborValue;
use log::info;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};

// Maximum incoming serialized request size.  Must match
// SerializedChannel::MAX_SIZE in hardware/baylibre/optee_hal_rust/gatekeeper/src/
// gatekeeper_hal_main.rs so the TA and HAL agree on
// the largest payload either side will accept.
const GK_MAX_BUFFER_LENGTH: usize = 8000;

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

fn handle_gk_request(params: &mut Parameters) -> Result<()> {
    // Serialized request in param[0] (MEMREF_INPUT).
    let req_data = optee_ta_common::read_input(&mut params.0, GK_MAX_BUFFER_LENGTH)?;

    // Not implemented yet: gk-ta needs the device-specific traits.
    let _ = req_data;
    let resp = PerformOpResponse::Err(ApiStatus::GeneralFailure as i32)
        .into_vec()
        .map_err(|_| Error::new(ErrorKind::Generic))?;

    // Serialized response in param[1] (MEMREF_OUTPUT).
    optee_ta_common::write_output(&mut params.1, &resp)
}
