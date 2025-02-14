//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::infra::errors::TransportConnectError;
use tokio::time::Duration;

use super::FakeStream;

#[derive(Clone, Debug)]
#[allow(dead_code)] // Keep all these cases around even if not all the tests use them.
pub enum Behavior {
    /// Let the connection attempt wait forever.
    ///
    /// This models the behavior of the underlying TCP `connect` syscall having no timeout.
    DelayForever,
    /// Fail the connection attempt with the provided error.
    Fail(fn() -> TransportConnectError),
    /// Wait some period of time before following the `then` behavior.
    Delay {
        delay: Duration,
        then: Box<Behavior>,
    },
    /// Connect the transport, applying the given modifiers to the returned stream.
    ReturnStream(Vec<fn(FakeStream) -> FakeStream>),
    /// Panic if invoked.
    Unreachable,
}

impl Behavior {
    pub(super) async fn apply(
        self,
    ) -> Result<Vec<fn(FakeStream) -> FakeStream>, TransportConnectError> {
        let mut next = self;

        loop {
            match next {
                Behavior::DelayForever => std::future::pending().await,
                Behavior::Delay { delay, then } => {
                    tokio::time::sleep(delay).await;
                    next = *then;
                }
                Behavior::Fail(make_error) => return Err(make_error()),
                Behavior::ReturnStream(stream) => return Ok(stream),
                Behavior::Unreachable => unreachable!("this test should not attempt to connect"),
            }
        }
    }
}
