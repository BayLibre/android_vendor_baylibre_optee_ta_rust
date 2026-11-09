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

use optee_utee_sys::{
    TEE_GetPropertyAsIdentity, TEE_Identity, TEE_LOGIN_PUBLIC, TEE_LOGIN_TRUSTED_APP,
    TEE_PROPSET_CURRENT_CLIENT, TEE_SUCCESS, TEE_UUID,
};

// Identity of the current-session TA's client.
pub enum ClientId {
    TA(TEE_UUID),
    Other,
}

impl ClientId {
    pub fn detect() -> Self {
        let prop_name = c"gpd.client.identity";
        let mut detected = TEE_Identity {
            login: TEE_LOGIN_PUBLIC,
            uuid: TEE_UUID { timeLow: 0, timeMid: 0, timeHiAndVersion: 0, clockSeqAndNode: [0; 8] },
        };
        // SAFETY: TEE_GetPropertyAsIdentity expects *const c_char for the name and
        // *mut TEE_Identity for the value, and both pointers are valid.
        match unsafe {
            TEE_GetPropertyAsIdentity(
                TEE_PROPSET_CURRENT_CLIENT,
                prop_name.as_ptr() as _,
                &mut detected,
            )
        } {
            TEE_SUCCESS if detected.login == TEE_LOGIN_TRUSTED_APP => {
                ClientId::TA(detected.uuid)
            }
            _ => ClientId::Other,
        }
    }
}
