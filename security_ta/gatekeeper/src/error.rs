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

//! Error conversion utilities for the Gatekeeper TA.

use gk_ta::Error as GkError;
use optee_utee::{Error as UteeError, ErrorKind};

/// Convert an OP-TEE error to a Gatekeeper error.
pub fn utee_to_gk_err(error: UteeError) -> GkError {
    log::error!("OP-TEE error: {}", error);
    match error.kind() {
        ErrorKind::OutOfMemory => GkError::AllocationFailed,
        ErrorKind::BadParameters => GkError::InvalidArgument,
        ErrorKind::ItemNotFound => GkError::NotFound,
        ErrorKind::MacInvalid | ErrorKind::SignatureInvalid => GkError::VerifyFailed,
        _ => GkError::Internal,
    }
}
