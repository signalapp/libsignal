//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;

use displaydoc::Display;
use tokio::time::Instant;

use crate::connection_manager::{ErrorClass, ErrorClassifier};
use crate::errors::LogSafeDisplay;
use crate::ServiceConnectionInfo;

/// For a service that needs to go through some initialization procedure
/// before it's ready for use, this enum describes its possible states.
#[derive(Debug)]
pub enum ServiceState<T, CE> {
    /// Service was not explicitly activated.
    Inactive,
    /// Contains an instance of the service which is initialized and ready to use.
    /// Also, since we're not actively listening for the event of service going inactive,
    /// the `CancellationToken` could be used to see if the service is actually running.
    Active(T, CancellationToken),
    /// The service is inactive and no initialization attempts are to be made
    /// until the `Instant` held by this object.
    Cooldown(Instant),
    /// Last connection attempt resulted in an error.
    Error(CE),
    /// Last connection attempt timed out.
    ConnectionTimedOut,
}

mod cancel_token;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancellationReason {
    ExplicitDisconnect,
    ServiceError,
    RemoteClose,
    ProtocolError,
}

pub type CancellationToken = cancel_token::CancellationToken<CancellationReason>;

pub trait RemoteAddressInfo {
    /// Provides information about the remote address the service is connected to
    fn connection_info(&self) -> ServiceConnectionInfo;
}

#[derive(Debug, Display)]
pub enum ConnectError<E: LogSafeDisplay> {
    /// Operation timed out
    Timeout { attempts: u16 },
    /// All attempted routes failed to connect
    AllRoutesFailed { attempts: u16 },
    /// Rejected by server: {0}
    RejectedByServer(E),
}

impl<E: LogSafeDisplay> ErrorClassifier for ConnectError<E> {
    fn classify(&self) -> ErrorClass {
        match self {
            ConnectError::Timeout { .. } | ConnectError::AllRoutesFailed { .. } => {
                ErrorClass::Intermittent
            }
            ConnectError::RejectedByServer(_) => ErrorClass::Fatal,
        }
    }
}

#[derive(Debug, Display)]
pub enum StateError {
    /// Service is in the inactive state
    Inactive,
    /// Service is unavailable due to the lost connection
    ServiceUnavailable,
}
