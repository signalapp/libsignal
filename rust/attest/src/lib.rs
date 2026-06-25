//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]

use libsignal_core::LogSafeDisplay;
use snow::error::{InitStage, PatternProblem, Prerequisite, StateProblem};

pub mod cds2;
pub mod client_connection;
pub mod constants;
pub mod dcap;
pub mod enclave;
pub mod hsm_enclave;
pub mod sgx_session;
pub mod snow_resolver;
pub mod svr2;

pub use util::get_sw_advisories;

mod cert_chain;
mod endian;
mod error;
mod expireable;
mod proto;
mod util;

/// Newtype wrapper for snow::Error for the purposes of logging.
/// See `libsignal_core::LogSafeDisplay`.
#[derive(displaydoc::Display, Debug, thiserror::Error)]
pub enum SnowError {
    /// {0}
    Known(snow::Error),
    /// Unknown snow Error
    Unknown,
}

impl From<snow::Error> for SnowError {
    fn from(value: snow::Error) -> Self {
        match &value {
            snow::Error::Pattern(pattern) => match pattern {
                PatternProblem::TooFewParameters
                | PatternProblem::TooManyParameters
                | PatternProblem::UnsupportedHandshakeType
                | PatternProblem::UnsupportedBaseType
                | PatternProblem::UnsupportedHashType
                | PatternProblem::UnsupportedDhType
                | PatternProblem::UnsupportedCipherType
                | PatternProblem::InvalidPsk
                | PatternProblem::DuplicateModifier
                | PatternProblem::UnsupportedModifier
                | PatternProblem::UnsupportedKemType => SnowError::Known(value),
            },
            snow::Error::Init(init) => match init {
                InitStage::ValidateKeyLengths
                | InitStage::ValidatePskLengths
                | InitStage::ValidateCipherTypes
                | InitStage::GetRngImpl
                | InitStage::GetDhImpl
                | InitStage::GetCipherImpl
                | InitStage::GetHashImpl
                | InitStage::GetKemImpl
                | InitStage::ValidatePskPosition
                | InitStage::ParameterOverwrite => SnowError::Known(value),
            },
            snow::Error::Prereq(prereq) => match prereq {
                Prerequisite::LocalPrivateKey | Prerequisite::RemotePublicKey => {
                    SnowError::Known(value)
                }
            },
            snow::Error::State(state) => match state {
                StateProblem::MissingKeyMaterial
                | StateProblem::MissingPsk
                | StateProblem::NotTurnToWrite
                | StateProblem::NotTurnToRead
                | StateProblem::HandshakeNotFinished
                | StateProblem::HandshakeAlreadyFinished
                | StateProblem::OneWay
                | StateProblem::Exhausted => SnowError::Known(value),
            },
            snow::Error::Input
            | snow::Error::Dh
            | snow::Error::Decrypt
            | snow::Error::Rng
            | snow::Error::Kem => SnowError::Known(value),
            _ => SnowError::Unknown,
        }
    }
}

impl LogSafeDisplay for SnowError {}
