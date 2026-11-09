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

use kmr_common;
use log;

pub trait Error {
    fn kmerr(e: Self) -> kmr_common::Error;
}

impl Error for optee_utee::Error {
    fn kmerr(error: optee_utee::Error) -> kmr_common::Error {
        log::error!("{}", error);
        match error.kind() {
            optee_utee::ErrorKind::BadParameters => {
                kmr_common::km_err!(InvalidArgument, "{}", error)
            }
            optee_utee::ErrorKind::MacInvalid | optee_utee::ErrorKind::SignatureInvalid => {
                kmr_common::km_err!(VerificationFailed, "{}", error)
            }
            optee_utee::ErrorKind::NotImplemented => {
                kmr_common::km_err!(Unimplemented, "{}", error)
            }
            optee_utee::ErrorKind::NotSupported => {
                kmr_common::km_err!(UnsupportedAlgorithm, "{}", error)
            }
            optee_utee::ErrorKind::OutOfMemory => {
                kmr_common::km_err!(MemoryAllocationFailed, "{}", error)
            }
            _ => kmr_common::km_err!(UnknownError, "{}", error),
        }
    }
}

impl Error for der::Error {
    fn kmerr(error: der::Error) -> kmr_common::Error {
        log::error!("der error: {}", error);
        kmr_common::km_err!(UnsupportedKeyFormat, "der error: {}", error)
    }
}

impl Error for pkcs1::Error {
    fn kmerr(error: pkcs1::Error) -> kmr_common::Error {
        log::error!("pkcs1 error: {}", error);
        kmr_common::km_err!(UnsupportedKeyFormat, "pkcs1 error: {}", error)
    }
}

impl Error for pkcs8::spki::Error {
    fn kmerr(error: pkcs8::spki::Error) -> kmr_common::Error {
        log::error!("spki error: {}", error);
        kmr_common::km_err!(UnsupportedKeyFormat, "spki error: {}", error)
    }
}

impl Error for sec1::Error {
    fn kmerr(error: sec1::Error) -> kmr_common::Error {
        log::error!("sec1 error: {}", error);
        kmr_common::km_err!(UnsupportedKeyFormat, "sec1 error: {}", error)
    }
}

impl Error for core::convert::Infallible {
    fn kmerr(error: core::convert::Infallible) -> kmr_common::Error {
        log::error!("Infallible error: {}", error);
        kmr_common::km_err!(MemoryAllocationFailed, "Infallible error: {}", error)
    }
}

impl Error for core::array::TryFromSliceError {
    fn kmerr(error: core::array::TryFromSliceError) -> kmr_common::Error {
        log::error!("TryFromSliceError error: {}", error);
        kmr_common::km_err!(MemoryAllocationFailed, "TryFromSliceError error: {}", error)
    }
}
