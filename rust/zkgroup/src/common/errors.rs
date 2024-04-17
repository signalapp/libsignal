//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkcredential::VerificationFailure;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Verification failure in zkgroup
pub struct ZkGroupVerificationFailure;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Deserialization failure in zkgroup
pub struct ZkGroupDeserializationFailure;

impl From<VerificationFailure> for ZkGroupVerificationFailure {
    fn from(VerificationFailure: VerificationFailure) -> Self {
        Self
    }
}
