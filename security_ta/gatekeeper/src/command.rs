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

//! Gatekeeper TA command definitions.
//!
//! This TA uses a single PROCESS command (param[0]=MEMREF_INPUT request,
//! param[1]=MEMREF_OUTPUT response) rather than the legacy C TA's direct GP
//! TEE command IDs (GK_ENROLL=0, GK_VERIFY=1, GK_DELETE_USER=2, etc.).
//! The HAL (hardware/baylibre/optee_hal_rust/gatekeeper) must use PROCESS.

// param[0]: MEMREF_INPUT  (serialized request)
// param[1]: MEMREF_OUTPUT (serialized response)
pub const PROCESS: u32 = 1026;
