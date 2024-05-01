//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkcredential::VerificationFailure;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Verification failure in zkgroup
pub struct ZkGroupVerificationFailure;

impl From<VerificationFailure> for ZkGroupVerificationFailure {
    fn from(VerificationFailure: VerificationFailure) -> Self {
        Self
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Failed to deserialize {0}
pub struct ZkGroupDeserializationFailure(&'static str);

impl ZkGroupDeserializationFailure {
    pub fn new<T>() -> Self {
        Self(std::any::type_name::<T>())
    }
}
