//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::{LogSafeDisplay, assert_log_safe_display};
use libsignal_net_infra::errors::RetryLater;
use libsignal_net_infra::ws::attested::AttestedConnectionError;
use libsignal_net_infra::ws::{WebSocketConnectError, WebSocketError};
use prost::Message as _;
use thiserror::Error;

use crate::proto::svr2 as proto;

pub mod ops;
use ops::{Svr2Protocol, do_backup, do_expose};

mod types;
use types::{MaxTries, Svr2Data};

use crate::svr2::types::{InvalidDataSize, InvalidMaxTries};

pub struct RestoreResult {
    pub data: Vec<u8>,
    pub tries_remaining: u32,
}

#[derive(Debug, Error, displaydoc::Display)]
pub enum Error {
    /// Connection error: {0}
    Connect(WebSocketConnectError),
    /// {0}
    RateLimited(RetryLater),
    /// Network error: {0}
    Service(#[from] WebSocketError),
    /// Protocol error after establishing a connection: {0}
    Protocol(String),
    /// Enclave attestation failed: {0}
    AttestationError(#[from] attest::enclave::Error),
    /// Failure to restore data. {tries_left} tries remaining.
    RestoreFailed { tries_left: u32 },
    /// Restore request failed: data not found on server
    DataMissing,
    /// Enclave not found
    EnclaveNotFound,
    /// No connection attempts succeeded before timeout
    AllConnectionAttemptsFailed,
}

impl LogSafeDisplay for Error {
    fn log_safe_display(&self) -> &Self
    where
        Self: Sized,
    {
        match self {
            Error::Connect(err) => {
                assert_log_safe_display!(err: &WebSocketConnectError);
                self
            }
            Error::RateLimited(err) => {
                assert_log_safe_display!(err: &RetryLater);
                self
            }
            Error::Service(err) => {
                assert_log_safe_display!(err: &WebSocketError);
                self
            }
            Error::AttestationError(err) => {
                assert_log_safe_display!(err: &attest::enclave::Error);
                self
            }
            Error::Protocol(_)
            | Error::RestoreFailed { .. }
            | Error::DataMissing
            | Error::EnclaveNotFound
            | Error::AllConnectionAttemptsFailed => self,
        }
    }
}

impl Error {
    pub fn from_enclave_error(err: crate::enclave::Error) -> Self {
        use crate::enclave::Error as E;
        match err {
            E::WebSocketConnect(inner) => Self::Connect(inner),
            E::RateLimited(inner) => Self::RateLimited(inner),
            E::WebSocket(inner) => Self::Service(inner),
            E::Protocol(inner) => Self::Protocol(inner.to_string()),
            E::AttestationError(inner) => Self::AttestationError(inner),
            E::AllConnectionAttemptsFailed => Self::AllConnectionAttemptsFailed,
        }
    }

    pub(crate) fn from_attested_error(err: AttestedConnectionError) -> Self {
        use AttestedConnectionError as E;
        match err {
            E::WebSocket(ws) => Self::Service(ws),
            E::Protocol(p) => Self::Protocol(p.to_string()),
            E::Attestation(a) => Self::AttestationError(a),
        }
    }
}

/// In-progress two-phase SVR2 backup operation.
///
/// SVR2 protocol recommends avoiding retrying a `BackupRequest` for the same
/// enclave/pin pair therefore we use a protobuf message so the session can be
/// easily serialized and stored between Backup and Expose.
///
/// Wrapping into a newtype struct to:
/// - Avoid exposing the protobuf-ness of BackupSession
/// - Enforce some invariants on construction
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum BackupSession {
    Partial {
        pin: [u8; 32],
        data: Svr2Data,
        max_tries: MaxTries,
    },
    Complete,
}

#[derive(Debug, Error, displaydoc::Display)]
pub enum BackupSessionDecodeError {
    /// Failed to decode BackupSession proto: {0}
    Decode(#[from] prost::DecodeError),
    /// Pin must be 32 bytes, got {0}
    InvalidPinLength(usize),
    /// {0}
    InvalidDataSize(#[from] InvalidDataSize),
    /// {0}
    InvalidMaxTries(#[from] InvalidMaxTries),
}

impl LogSafeDisplay for BackupSessionDecodeError {}

impl BackupSession {
    pub fn serialize(&self) -> Vec<u8> {
        let proto = match self {
            BackupSession::Partial {
                pin,
                data,
                max_tries,
            } => proto::BackupSession {
                pin: pin.to_vec(),
                data: data.as_ref().to_vec(),
                max_tries: (*max_tries).into(),
                is_completed: false,
            },
            BackupSession::Complete => {
                proto::BackupSession {
                    is_completed: true,
                    // These values should not be used for a complete session.
                    // Intentionally initializing them with invalid values.
                    pin: vec![],
                    data: vec![],
                    max_tries: 0,
                }
            }
        };
        proto.encode_to_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, BackupSessionDecodeError> {
        let proto::BackupSession {
            pin,
            data,
            max_tries,
            is_completed,
        } = proto::BackupSession::decode(bytes)?;
        if is_completed {
            Ok(BackupSession::Complete)
        } else {
            let len = pin.len();
            let pin = pin
                .try_into()
                .map_err(|_| BackupSessionDecodeError::InvalidPinLength(len))?;
            let data = Svr2Data::try_from(data)?;
            let max_tries = MaxTries::try_from(max_tries)?;
            Ok(BackupSession::Partial {
                pin,
                data,
                max_tries,
            })
        }
    }

    /// Initiate the backup.
    ///
    /// Attempts creating a backup by performing both the Backup and Expose
    /// operations. If Backup fails - returns an error. Can be safely retried.
    /// If Backup succeeds - tries to perform Expose on the same connection.
    /// Regardless of the result of Expose creates a backup session object that
    /// you can invoke `finish` on to finalize the backup.
    ///
    /// This design tries to make it harder to accidentally retry a successful
    /// Backup with the same data as warned against by the SVR2 protocol.
    pub async fn start<T: Svr2Protocol>(
        conn: &mut T,
        pin: [u8; 32],
        data: Svr2Data,
        max_tries: MaxTries,
    ) -> Result<BackupSession, Error> {
        do_backup(conn, &pin, &data, max_tries).await?;
        match do_expose(conn, &data).await {
            Err(e) => {
                log::info!("SVR2 Expose failed: {e}");
                Ok(Self::Partial {
                    pin,
                    data,
                    max_tries,
                })
            }
            Ok(()) => Ok(Self::Complete),
        }
    }

    /// Finishes the backup session.
    ///
    /// Performs the Expose operation if it failed in `start`, otherwise a noop.
    /// Will only poll the `conn` future if the connection is needed.
    pub async fn finish<T: Svr2Protocol>(
        &mut self,
        conn: impl Future<Output = Result<T, Error>>,
    ) -> Result<(), Error> {
        match self {
            BackupSession::Complete => Ok(()),
            BackupSession::Partial {
                pin: _,
                data,
                max_tries: _,
            } => {
                let mut conn = conn.await?;
                log::info!("Detached SVR2 Expose");
                do_expose(&mut conn, data).await?;
                *self = BackupSession::Complete;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Formatter};

    use assert_matches::assert_matches;
    use futures_util::FutureExt as _;
    use test_case::test_matrix;

    use super::ops::{do_delete, do_restore};
    use super::*;

    const PIN: [u8; 32] = [7u8; 32];
    const DATA: &[u8] = &[42u8; 32];
    const MAX_TRIES: MaxTries = match MaxTries::new(5) {
        Ok(v) => v,
        Err(_) => panic!("invalid test data"),
    };

    fn test_data() -> Svr2Data {
        DATA.to_vec().try_into().expect("valid data")
    }

    #[test]
    fn serialize_deserialize_round_trip_preserves_fields() {
        let mut conn = successful_test_connection();
        let session = BackupSession::start(&mut conn, PIN, test_data(), MAX_TRIES)
            .now_or_never()
            .expect("sync")
            .expect("valid test data");
        let bytes = session.serialize();
        let decoded = BackupSession::deserialize(&bytes).unwrap();
        assert_eq!(decoded, session);
    }

    #[test_matrix([true, false])]
    fn deserialize_bad_pin_length(is_completed: bool) {
        let bytes = proto::BackupSession {
            pin: vec![0u8; 16],
            data: DATA.to_vec(),
            max_tries: MAX_TRIES.into(),
            is_completed,
        }
        .encode_to_vec();
        if is_completed {
            assert_matches!(BackupSession::deserialize(&bytes), Ok(_))
        } else {
            assert_matches!(
                BackupSession::deserialize(&bytes),
                Err(BackupSessionDecodeError::InvalidPinLength(16))
            );
        }
    }

    #[test]
    fn deserialize_rejects_bad_input() {
        assert_matches!(
            BackupSession::deserialize(&[0; 42]),
            Err(BackupSessionDecodeError::Decode(_))
        );
    }

    struct TestConnection<T>(T);

    impl<T> Debug for TestConnection<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("TestConnection{...}")
        }
    }

    impl<T> Svr2Protocol for TestConnection<T>
    where
        T: Fn(proto::Request) -> Result<proto::Response, Error>,
    {
        async fn exchange(&mut self, request: proto::Request) -> Result<proto::Response, Error> {
            (self.0)(request)
        }
    }

    fn backup_response(status: proto::backup_response::Status) -> proto::Response {
        proto::Response {
            inner: Some(proto::response::Inner::Backup(proto::BackupResponse {
                status: status.into(),
            })),
        }
    }

    fn expose_response(status: proto::expose_response::Status) -> proto::Response {
        proto::Response {
            inner: Some(proto::response::Inner::Expose(proto::ExposeResponse {
                status: status.into(),
            })),
        }
    }

    fn restore_response(
        status: proto::restore_response::Status,
        tries: u32,
        data: Vec<u8>,
    ) -> proto::Response {
        proto::Response {
            inner: Some(proto::response::Inner::Restore(proto::RestoreResponse {
                status: status.into(),
                data,
                tries,
            })),
        }
    }

    fn delete_response() -> proto::Response {
        proto::Response {
            inner: Some(proto::response::Inner::Delete(proto::DeleteResponse {})),
        }
    }

    fn successful_test_connection()
    -> TestConnection<impl Fn(proto::Request) -> Result<proto::Response, Error>> {
        TestConnection(|request: proto::Request| match request {
            proto::Request {
                inner: Some(proto::request::Inner::Backup(_)),
            } => Ok(backup_response(proto::backup_response::Status::Ok)),
            proto::Request {
                inner: Some(proto::request::Inner::Expose(proto::ExposeRequest { data })),
            } if data == DATA => Ok(expose_response(proto::expose_response::Status::Ok)),
            proto::Request {
                inner: Some(proto::request::Inner::Restore(_)),
            } => Ok(restore_response(
                proto::restore_response::Status::Ok,
                MAX_TRIES.into(),
                DATA.to_vec(),
            )),
            proto::Request {
                inner: Some(proto::request::Inner::Delete(_)),
            } => Ok(delete_response()),
            _ => panic!("Unexpected request: {request:?}"),
        })
    }

    #[tokio::test]
    async fn backup_one_shot() {
        let mut conn = successful_test_connection();

        let mut session = BackupSession::start(&mut conn, PIN, test_data(), MAX_TRIES)
            .await
            .expect("can one-shot a backup");
        assert_matches!(session, BackupSession::Complete);

        let conn = TestConnection(|_| panic!("unexpected exchange over connection"));

        session
            .finish(async { Ok(conn) })
            .await
            .expect("finish should be a noop");
    }

    #[tokio::test]
    async fn backup_expose_fail() {
        let mut conn = TestConnection(|request: proto::Request| match request {
            proto::Request {
                inner: Some(proto::request::Inner::Backup(_)),
            } => Ok(backup_response(proto::backup_response::Status::Ok)),
            proto::Request {
                inner: Some(proto::request::Inner::Expose(_)),
            } => Ok(expose_response(proto::expose_response::Status::Error)),
            _ => panic!("Unexpected request: {request:?}"),
        });

        let mut session = BackupSession::start(&mut conn, PIN, test_data(), MAX_TRIES)
            .await
            .expect("start should succeed");
        assert_matches!(session, BackupSession::Partial { .. });

        // Try finish on a still failing connection
        session
            .finish(async { Ok(conn) })
            .await
            .expect_err("still failing");
        assert_matches!(session, BackupSession::Partial { .. });

        // Now make Expose succeed
        let conn = TestConnection(|request| match request {
            proto::Request {
                inner: Some(proto::request::Inner::Expose(proto::ExposeRequest { data })),
            } if data == DATA => Ok(expose_response(proto::expose_response::Status::Ok)),
            _ => panic!("Unexpected request: {request:?}"),
        });

        session
            .finish(async { Ok(conn) })
            .await
            .expect("should succeed now");
        assert_matches!(session, BackupSession::Complete);
    }

    #[tokio::test]
    async fn do_backup_non_ok_status_is_protocol_error() {
        let mut conn =
            TestConnection(|_| Ok(backup_response(proto::backup_response::Status::Unset)));
        assert_matches!(
            do_backup(&mut conn, &PIN, &test_data(), MAX_TRIES).await,
            Err(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_backup_wrong_response_kind_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(delete_response()));
        assert_matches!(
            do_backup(&mut conn, &PIN, &test_data(), MAX_TRIES,).await,
            Err(Error::Protocol(_))
        );
    }

    #[test_matrix([
        proto::expose_response::Status::Unset,
        proto::expose_response::Status::Error,
    ])]
    #[tokio::test]
    async fn do_expose_non_ok_status_is_protocol_error(status: proto::expose_response::Status) {
        let mut conn = TestConnection(move |_| Ok(expose_response(status)));
        assert_matches!(
            do_expose(&mut conn, &test_data()).await,
            Err(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_expose_wrong_response_kind_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(delete_response()));
        assert_matches!(
            do_expose(&mut conn, &test_data()).await,
            Err(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_restore_pin_mismatch() {
        let mut conn = TestConnection(|_| {
            Ok(restore_response(
                proto::restore_response::Status::PinMismatch,
                2,
                vec![],
            ))
        });
        assert_matches!(
            do_restore(&mut conn, &PIN).await.err(),
            Some(Error::RestoreFailed { tries_left: 2 })
        );
    }

    #[tokio::test]
    async fn do_restore_missing() {
        let mut conn = TestConnection(|_| {
            Ok(restore_response(
                proto::restore_response::Status::Missing,
                0,
                vec![],
            ))
        });
        assert_matches!(
            do_restore(&mut conn, &PIN).await.err(),
            Some(Error::DataMissing)
        );
    }

    #[tokio::test]
    async fn do_restore_unset_status_is_protocol_error() {
        let mut conn = TestConnection(|_| {
            Ok(restore_response(
                proto::restore_response::Status::Unset,
                0,
                vec![],
            ))
        });
        assert_matches!(
            do_restore(&mut conn, &PIN).await.err(),
            Some(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_restore_wrong_response_kind_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(delete_response()));
        assert_matches!(
            do_restore(&mut conn, &PIN).await.err(),
            Some(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_remove_wrong_response_kind_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(backup_response(proto::backup_response::Status::Ok)));
        assert_matches!(do_delete(&mut conn).await, Err(Error::Protocol(_)));
    }

    fn empty_response() -> proto::Response {
        proto::Response { inner: None }
    }

    #[tokio::test]
    async fn do_backup_empty_inner_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(empty_response()));
        assert_matches!(
            do_backup(&mut conn, &PIN, &test_data(), MAX_TRIES,).await,
            Err(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_expose_empty_inner_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(empty_response()));
        assert_matches!(
            do_expose(&mut conn, &test_data()).await,
            Err(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_restore_empty_inner_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(empty_response()));
        assert_matches!(
            do_restore(&mut conn, &PIN).await.err(),
            Some(Error::Protocol(_))
        );
    }

    #[tokio::test]
    async fn do_remove_empty_inner_is_protocol_error() {
        let mut conn = TestConnection(|_| Ok(empty_response()));
        assert_matches!(do_delete(&mut conn).await, Err(Error::Protocol(_)));
    }
}
