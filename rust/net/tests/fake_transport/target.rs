//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::num::NonZeroU16;
use std::sync::Arc;

use libsignal_net::infra::host::Host;
use libsignal_net::infra::{ConnectionParams, TransportConnectionParams};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FakeTransportTarget {
    pub host: Host<Arc<str>>,
    pub port: NonZeroU16,
}

impl Display for FakeTransportTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { host, port } = self;
        write!(f, "{host}:{port}")
    }
}

impl From<TransportConnectionParams> for FakeTransportTarget {
    fn from(value: TransportConnectionParams) -> Self {
        Self {
            host: value.tcp_host,
            port: value.port,
        }
    }
}
impl From<ConnectionParams> for FakeTransportTarget {
    fn from(value: ConnectionParams) -> Self {
        value.transport.into()
    }
}
