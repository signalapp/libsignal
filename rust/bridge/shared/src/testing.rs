//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(unused_imports)]

use futures_util::FutureExt;
use libsignal_bridge_macros::*;
use libsignal_protocol::SignalProtocolError;

use std::future::Future;

use crate::support::*;
use crate::*;

struct NonSuspendingBackgroundThreadRuntime;
bridge_handle!(
    NonSuspendingBackgroundThreadRuntime,
    ffi = false,
    jni = TESTING_1NonSuspendingBackgroundThreadRuntime,
    node = false
);

impl AsyncRuntime for NonSuspendingBackgroundThreadRuntime {
    fn run_future(&self, future: impl Future<Output = ()> + Send + 'static) {
        std::thread::spawn(move || {
            future
                .now_or_never()
                .expect("no need to suspend in testing methods")
        });
    }
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false, node = false)]
async fn TESTING_FutureSuccess(input: u8) -> i32 {
    i32::from(input) * 2
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false, node = false)]
async fn TESTING_FuturePanic(_input: u8) -> i32 {
    panic!("failure")
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false, node = false)]
async fn TESTING_FutureFailure(_input: u8) -> Result<i32, SignalProtocolError> {
    Err(SignalProtocolError::InvalidArgument("failure".to_string()))
}
