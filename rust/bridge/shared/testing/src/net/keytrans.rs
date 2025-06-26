//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_types::keytrans::BridgeError;
use libsignal_net_chat::api::RequestError;

use crate::*;

#[bridge_fn]
fn TESTING_KeyTransFatalVerificationFailure() -> Result<(), BridgeError> {
    Err(RequestError::Other(
        libsignal_keytrans::Error::VerificationFailed(
            "this is a fatal verification failure".to_string(),
        )
        .into(),
    )
    .into())
}

#[bridge_fn]
fn TESTING_KeyTransNonFatalVerificationFailure() -> Result<(), BridgeError> {
    Err(RequestError::Other(
        libsignal_keytrans::Error::BadData("this is a non-fatal verification failure").into(),
    )
    .into())
}

#[bridge_fn]
fn TESTING_KeyTransChatSendError() -> Result<(), BridgeError> {
    Err(RequestError::Timeout.into())
}
