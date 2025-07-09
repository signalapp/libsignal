// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_infra::ws::WebSocketServiceError;
use libsignal_net_infra::ws2::attested::AttestedConnectionError;
use libsignal_svrb::{Backup4, Secret};
use thiserror::Error;

mod ppss_ops;

pub mod traits;
use traits::*;

#[cfg(any(test, feature = "test-util"))]
pub mod direct;

use crate::ws::WebSocketServiceConnectError;

/// SVRB-specific error type
///
/// In its essence it is simply a union of two other error types:
/// - libsignal_svrb::Error for the errors originating in the PPSS implementation. Most of them are
///   unlikely due to the way higher level APIs invoke the lower-level primitives from
///   libsignal_svrb.
/// - libsignal_net::svr::Error for network related errors.
#[derive(Debug, Error, displaydoc::Display)]
#[ignore_extra_doc_attributes]
pub enum Error {
    /// Connection error: {0}
    Connect(WebSocketServiceConnectError),
    /// Network error: {0}
    Service(#[from] WebSocketServiceError),
    /// Protocol error after establishing a connection: {0}
    Protocol(String),
    /// Enclave attestation failed: {0}
    AttestationError(attest::enclave::Error),
    /// SVRB request failed with status {0}
    RequestFailed(libsignal_svrb::ErrorStatus),
    /// Failure to restore data. {0} tries remaining.
    ///
    /// This could be caused by an invalid password or share set.
    RestoreFailed(u32),
    /// Restore request failed with MISSING status,
    ///
    /// This could mean either the data was never backed-up or we ran out of attempts to restore
    /// it.
    DataMissing,
    /// Connect timed out
    ConnectionTimedOut,
}

impl From<attest::enclave::Error> for Error {
    fn from(err: attest::enclave::Error) -> Self {
        Self::AttestationError(err)
    }
}

impl From<libsignal_svrb::Error> for Error {
    fn from(err: libsignal_svrb::Error) -> Self {
        use libsignal_svrb::Error as LogicError;
        match err {
            LogicError::RestoreFailed(tries_remaining) => Self::RestoreFailed(tries_remaining),
            LogicError::BadResponseStatus(libsignal_svrb::ErrorStatus::Missing)
            | LogicError::BadResponseStatus4(libsignal_svrb::V4Status::Missing) => {
                Self::DataMissing
            }
            LogicError::BadData
            | LogicError::BadResponse
            | LogicError::NumServers { .. }
            | LogicError::NoUsableVersion
            | LogicError::BadResponseStatus4(_)
            | LogicError::BadResponseStatus(_) => Self::Protocol(err.to_string()),
        }
    }
}

impl From<super::svr::Error> for Error {
    fn from(err: super::svr::Error) -> Self {
        use super::svr::Error as SvrError;
        match err {
            SvrError::WebSocketConnect(inner) => Self::Connect(inner),
            SvrError::WebSocket(inner) => Self::Service(inner),
            SvrError::Protocol(error) => Self::Protocol(error.to_string()),
            SvrError::AttestationError(inner) => Self::AttestationError(inner),
            SvrError::ConnectionTimedOut => Self::ConnectionTimedOut,
        }
    }
}

impl From<AttestedConnectionError> for Error {
    fn from(err: AttestedConnectionError) -> Self {
        Self::from(super::svr::Error::from(err))
    }
}

/// Attempt a restore from a pair of SVRB instances.
///
/// The function is meant to be used in the registration flow, when the client
/// app does not yet know whether it is supposed to be trusting one set of enclaves
/// or another. Therefore, it first reads from the primary falling back to the
/// secondary enclaves only if the primary returned `DataMissing`, that is, the
/// data has not been migrated yet. Any other error terminates the whole operation
/// and will need to be retried.
///
/// The choice of terms "primary" and "fallback" is, perhaps, a little confusing
/// when thinking about the enclave migration, where they would be called,
/// respectively, "next" and "current", but ordering of parameters and actions in
/// the body of the function make "primary" and "fallback" a better fit.
pub async fn restore_with_fallback<Primary, Fallback>(
    clients: (&Primary, &Fallback),
    password: &str,
) -> Result<Secret, Error>
where
    Primary: Restore + Sync,
    Fallback: Restore + Sync,
{
    let (primary_conn, fallback_conn) = clients;

    match primary_conn.restore(password).await {
        Err(Error::DataMissing) => {}
        result @ (Err(_) | Ok(_)) => return result,
    }
    fallback_conn.restore(password).await
}

#[cfg(feature = "test-util")]
pub mod test_support {

    use crate::auth::Auth;
    use crate::enclave::PpssSetup;
    use crate::env::SvrBEnv;
    use crate::svrb::direct::DirectConnect as _;

    impl SvrBEnv<'static> {
        /// Simplest way to connect to an SVRB Environment in integration tests, command
        /// line tools, and examples.
        pub async fn connect_directly(
            &self,
            auth: &Auth,
        ) -> <Self as PpssSetup>::ConnectionResults {
            let endpoints = self.sgx();
            endpoints.connect(auth).await
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use libsignal_svrb::{Backup4, Secret};

    use super::*;

    struct TestSvrBClient {
        prepare_fn: fn() -> Backup4,
        finalize_fn: fn() -> Result<(), Error>,
        restore_fn: fn() -> Result<Secret, Error>,
        remove_fn: fn() -> Result<(), Error>,
    }

    impl Default for TestSvrBClient {
        fn default() -> Self {
            Self {
                prepare_fn: || panic!("Unexpected call to prepare_fn"),
                finalize_fn: || panic!("Unexpected call to backup"),
                restore_fn: || panic!("Unexpected call to restore"),
                remove_fn: || panic!("Unexpected call to remove"),
            }
        }
    }

    #[async_trait]
    impl Backup for TestSvrBClient {
        fn prepare(&self, _password: &str) -> Backup4 {
            (self.prepare_fn)()
        }
        async fn finalize(&self, _b4: &Backup4) -> Result<(), Error> {
            (self.finalize_fn)()
        }
    }

    #[async_trait]
    impl Remove for TestSvrBClient {
        async fn remove(&self) -> Result<(), Error> {
            (self.remove_fn)()
        }
    }

    #[async_trait]
    impl Restore for TestSvrBClient {
        async fn restore(&self, _password: &str) -> Result<Secret, Error> {
            (self.restore_fn)()
        }
    }

    #[async_trait]
    impl Query for TestSvrBClient {
        async fn query(&self) -> Result<u32, Error> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn restore_with_fallback_primary_success() {
        let primary = TestSvrBClient {
            restore_fn: || Ok(Secret::default()),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || panic!("Must not be called"),
            ..TestSvrBClient::default()
        };

        let result = restore_with_fallback((&primary, &fallback), "").await;
        assert_matches!(result, Ok(output4) => assert_eq!(output4, Secret::default()));
    }

    #[tokio::test]
    async fn restore_with_fallback_primary_fatal_error() {
        let primary = TestSvrBClient {
            restore_fn: || Err(Error::ConnectionTimedOut),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || panic!("Must not be called"),
            ..TestSvrBClient::default()
        };

        let result = restore_with_fallback((&primary, &fallback), "").await;
        assert_matches!(result, Err(Error::ConnectionTimedOut));
    }

    #[tokio::test]
    async fn restore_with_fallback_fallback_error() {
        let primary = TestSvrBClient {
            restore_fn: || Err(Error::DataMissing),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || Err(Error::RestoreFailed(31415)),
            ..TestSvrBClient::default()
        };
        let result = restore_with_fallback((&primary, &fallback), "").await;
        assert_matches!(result, Err(Error::RestoreFailed(31415)));
    }

    #[tokio::test]
    async fn restore_with_fallback_fallback_success() {
        let primary = TestSvrBClient {
            restore_fn: || Err(Error::DataMissing),
            ..TestSvrBClient::default()
        };
        let fallback = TestSvrBClient {
            restore_fn: || Ok(Secret::default()),
            ..TestSvrBClient::default()
        };
        let result = restore_with_fallback((&primary, &fallback), "").await;
        assert_matches!(result, Ok(output4) => assert_eq!(output4, Secret::default()));
    }
}
