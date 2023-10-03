//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(unused_imports, dead_code)]

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
    jni = TESTING_1NonSuspendingBackgroundThreadRuntime
);

impl<F> AsyncRuntime<F> for NonSuspendingBackgroundThreadRuntime
where
    F: Future<Output = ()> + Send + 'static,
{
    fn run_future(&self, future: F) {
        std::thread::spawn(move || {
            future
                .now_or_never()
                .expect("no need to suspend in testing methods")
        });
    }
}

#[bridge_fn(ffi = false, jni = false)]
fn TESTING_NonSuspendingBackgroundThreadRuntime_New() -> NonSuspendingBackgroundThreadRuntime {
    NonSuspendingBackgroundThreadRuntime
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false)]
async fn TESTING_FutureSuccess(input: u8) -> i32 {
    i32::from(input) * 2
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false)]
async fn TESTING_FuturePanic(_input: u8) -> i32 {
    panic!("failure")
}

#[bridge_io(NonSuspendingBackgroundThreadRuntime, ffi = false)]
async fn TESTING_FutureFailure(_input: u8) -> Result<i32, SignalProtocolError> {
    Err(SignalProtocolError::InvalidArgument("failure".to_string()))
}
