//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_keytrans::{StoredAccountData, StoredMonitoringData};
use libsignal_net_chat::api::RequestError;
use libsignal_net_chat::api::keytrans::Error as KeyTransError;
use prost::Message;

use crate::*;

#[bridge_fn]
fn TESTING_KeyTransFatalVerificationFailure() -> Result<(), RequestError<KeyTransError>> {
    Err(RequestError::Other(
        libsignal_keytrans::Error::VerificationFailed(
            "this is a fatal verification failure".to_string(),
        )
        .into(),
    ))
}

#[bridge_fn]
fn TESTING_KeyTransNonFatalVerificationFailure() -> Result<(), RequestError<KeyTransError>> {
    Err(RequestError::Other(
        libsignal_keytrans::Error::BadData("this is a non-fatal verification failure".to_string())
            .into(),
    ))
}

#[bridge_fn]
fn TESTING_KeyTransChatSendError() -> Result<(), RequestError<KeyTransError>> {
    Err(RequestError::Timeout)
}

#[bridge_fn]
fn TESTING_KeyTransStoredAccountData() -> Vec<u8> {
    StoredAccountData {
        aci: Some(StoredMonitoringData {
            pos: 1,
            ..Default::default()
        }),
        e164: Some(StoredMonitoringData {
            pos: 2,
            ..Default::default()
        }),
        username_hash: Some(StoredMonitoringData {
            pos: 3,
            ..Default::default()
        }),
        last_tree_head: None,
    }
    .encode_to_vec()
}
