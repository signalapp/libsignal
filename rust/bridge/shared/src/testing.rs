//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(unused_imports)]

use libsignal_bridge_macros::*;
use libsignal_protocol::SignalProtocolError;

use crate::support::*;
use crate::*;

#[bridge_io(ffi = false, node = false)]
async fn TESTING_FutureSuccess(input: u8) -> i32 {
    i32::from(input) * 2
}

#[bridge_io(ffi = false, node = false)]
async fn TESTING_FuturePanic(_input: u8) -> i32 {
    panic!("failure")
}

#[bridge_io(ffi = false, node = false)]
async fn TESTING_FutureFailure(_input: u8) -> Result<i32, SignalProtocolError> {
    Err(SignalProtocolError::InvalidArgument("failure".to_string()))
}
