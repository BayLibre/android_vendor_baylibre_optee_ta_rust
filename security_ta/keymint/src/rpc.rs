//
// Copyright (C) 2022 The Android Open Source Project
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

//! Device traits for `IRemotelyProvisionedComponent`: keys derived from the
//! hardware unique key. The DICE chain must come from the boot chain, which
//! does not provide one yet: RKP is not available.
use alloc::vec::Vec;
use kmr_common::{crypto, rpc_err, Error};
use kmr_ta::device::{DiceInfo, RetrieveRpcArtifacts, RpcV2Req};
use kmr_wire::rpc;

pub struct RpcArtifacts;

impl RetrieveRpcArtifacts for RpcArtifacts {
    fn derive_bytes_from_hbk(
        &self,
        _hkdf: &dyn crypto::Hkdf,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let key = crate::crypto::derive_hbk(context, output_len)?;
        Ok(key.0.clone())
    }

    fn get_dice_info<'a>(&self, _test_mode: rpc::TestMode) -> Result<DiceInfo, Error> {
        Err(rpc_err!(Failed, "no DICE chain available"))
    }

    fn sign_data(
        &self,
        _ec: &dyn crypto::Ec,
        _data: &[u8],
        _rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error> {
        Err(rpc_err!(Failed, "no DICE chain available"))
    }
}
