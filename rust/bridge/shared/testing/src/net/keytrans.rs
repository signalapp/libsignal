//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use libsignal_net::keytrans::Error;

use crate::*;

#[bridge_fn]
fn TESTING_KeyTransFatalVerificationFailure() -> Result<(), Error> {
    Err(Error::FatalVerificationFailure(
        "this is a fatal verification failure".to_string(),
    ))
}

#[bridge_fn]
fn TESTING_KeyTransNonFatalVerificationFailure() -> Result<(), Error> {
    Err(Error::NonFatalVerificationFailure(
        "this is a non-fatal verification failure".to_string(),
    ))
}

#[bridge_fn]
fn TESTING_KeyTransChatSendError() -> Result<(), Error> {
    Err(Error::from(libsignal_net::chat::SendError::Disconnected))
}
