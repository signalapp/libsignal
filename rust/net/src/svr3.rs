//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU32;

use bincode::Options as _;
use libsignal_net_infra::errors::LogSafeDisplay;
use libsignal_net_infra::ws::WebSocketServiceError;
use libsignal_net_infra::ws2::attested::AttestedConnectionError;
use libsignal_svr3::{EvaluationResult, MaskedSecret};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod ppss_ops;

pub mod direct;

pub mod traits;
use traits::*;

use crate::ws::WebSocketServiceConnectError;

// Versions:
//   0: XOR'd secret
//   1: AES-GCM encrypted secret
const MASKED_SHARE_SET_FORMAT: u8 = 1;

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Default))]
pub struct OpaqueMaskedShareSet {
    inner: SerializableMaskedShareSet,
}

// Non pub version of svr3::MaskedSecret used for serialization
#[derive(Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq, Default))]
struct SerializableMaskedShareSet {
    server_ids: Vec<u64>,
    masked_secret: Vec<u8>,
}

impl From<MaskedSecret> for SerializableMaskedShareSet {
    fn from(value: MaskedSecret) -> Self {
        Self {
            server_ids: value.server_ids,
            masked_secret: value.masked_secret,
        }
    }
}

impl SerializableMaskedShareSet {
    fn into(self) -> MaskedSecret {
        MaskedSecret {
            server_ids: self.server_ids,
            masked_secret: self.masked_secret,
        }
    }
}

#[derive(Debug)]
pub struct SerializeError;

#[derive(Debug, Eq, PartialEq, displaydoc::Display, Error)]
pub enum DeserializeError {
    /// Unexpected OpaqueMaskedShareSet serialization format version {0}
    BadVersion(u8),
    /// Unsupported OpaqueMaskedShareSet serialization format
    BadFormat,
}

impl LogSafeDisplay for DeserializeError {}

impl OpaqueMaskedShareSet {
    fn new(inner: MaskedSecret) -> Self {
        Self {
            inner: inner.into(),
        }
    }
    fn into_inner(self) -> MaskedSecret {
        self.inner.into()
    }

    // OpaqueMaskedShareSet should be presented to the clients as an opaque blob,
    // therefore serialize/deserialize should be the only public APIs for it.
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let mut buf = vec![MASKED_SHARE_SET_FORMAT];

        Self::bincode_options()
            .serialize_into(&mut buf, &self.inner)
            .map_err(|_| SerializeError)?;
        Ok(buf)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        match bytes {
            [] => Err(DeserializeError::BadFormat),
            [MASKED_SHARE_SET_FORMAT, data @ ..] => Self::bincode_deserialize(data),
            [v, ..] => Err(DeserializeError::BadVersion(*v)),
        }
    }

    fn bincode_options() -> impl bincode::Options {
        // Using options to reject possible trailing bytes but retain the fixed representation for integers.
        // See https://docs.rs/bincode/latest/bincode/config/index.html#options-struct-vs-bincode-functions
        bincode::config::DefaultOptions::new()
            .reject_trailing_bytes()
            .with_fixint_encoding()
    }

    fn bincode_deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        let inner = Self::bincode_options()
            .deserialize(bytes)
            .map_err(|_| DeserializeError::BadFormat)?;
        Ok(Self { inner })
    }
}

/// SVR3-specific error type
///
/// In its essence it is simply a union of three other error types:
/// - libsignal_svr3::Error for the errors originating in the PPSS implementation. Most of them are
///   unlikely due to the way higher level APIs invoke the lower-level primitives from
///   libsignal_svr3.
/// - DeserializeError for the errors deserializing the OpaqueMaskedShareSet that is stored as a
///   simple blob by the clients and may be corrupted.
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
    /// SVR3 request failed with status {0}
    RequestFailed(libsignal_svr3::ErrorStatus),
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
    /// Rotation machine took too many steps
    RotationMachineTooManySteps,
}

impl From<DeserializeError> for Error {
    fn from(err: DeserializeError) -> Self {
        Self::Protocol(format!("DeserializationError {err}"))
    }
}

impl From<attest::enclave::Error> for Error {
    fn from(err: attest::enclave::Error) -> Self {
        Self::AttestationError(err)
    }
}

impl From<libsignal_svr3::Error> for Error {
    fn from(err: libsignal_svr3::Error) -> Self {
        use libsignal_svr3::Error as LogicError;
        match err {
            LogicError::RestoreFailed(tries_remaining) => Self::RestoreFailed(tries_remaining),
            LogicError::BadResponseStatus(libsignal_svr3::ErrorStatus::Missing)
            | LogicError::BadResponseStatus4(libsignal_svr3::V4Status::Missing) => {
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

/// Attempt a restore from a pair of SVR3 instances.
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
    share_set: OpaqueMaskedShareSet,
    rng: &mut (impl CryptoRngCore + Send),
) -> Result<EvaluationResult, Error>
where
    Primary: Restore + Sync,
    Fallback: Restore + Sync,
{
    let (primary_conn, fallback_conn) = clients;

    match primary_conn.restore(password, share_set.clone(), rng).await {
        Err(Error::DataMissing) => {}
        result @ (Err(_) | Ok(_)) => return result,
    }
    fallback_conn.restore(password, share_set, rng).await
}

/// Move the backup from `RemoveFrom` to `BackupTo`, representing previous and
/// current SVR3 environments, respectively.
///
/// No data is _read_ from `RemoveFrom` (types guarantee that), and instead must
/// be provided by the caller just like for an ordinary `backup` call.
///
/// Moving includes _attempting_ deletion from `RemoveFrom` that can fail, in
/// which case the error will be ignored. The other alternative implementations
/// could be:
/// - Do not attempt deleting from `RemoveFrom`.
///   This would leave the data for harvesting longer than necessary, even
///   though the migration period is expected to be relatively short, and the
///   set of `RemoveFrom` enclaves would have been deleted in the end.
/// - Ignore the successful write to `BackupTo`.
///   Despite sounding like a better option, it would make `restore_with_fallback`
///   more complicated, as the data may have been written to `BackupTo`, thus
///   rendering it impossible to be used for all restores unconditionally.
///
/// Using fine-grained SVR3 traits `Remove` and `Backup` guarantees that only
/// those operations will possibly happen, that is, no removes will happen from
/// `BackupTo` client, and no backups to `RemoveFrom`.
pub async fn migrate_backup<RemoveFrom, BackupTo>(
    clients: (&RemoveFrom, &BackupTo),
    password: &str,
    secret: [u8; 32],
    max_tries: NonZeroU32,
    rng: &mut (impl CryptoRngCore + Send),
) -> Result<OpaqueMaskedShareSet, Error>
where
    RemoveFrom: Remove + Sync,
    BackupTo: Backup + Sync,
{
    let (from_client, to_client) = clients;
    let share_set = to_client.backup(password, secret, max_tries, rng).await?;
    let _ = from_client.remove().await;
    Ok(share_set)
}

#[cfg(feature = "test-util")]
pub mod test_support {

    use crate::auth::Auth;
    use crate::enclave::PpssSetup;
    use crate::env::Svr3Env;
    use crate::svr3::direct::DirectConnect as _;

    impl Svr3Env<'static> {
        /// Simplest way to connect to an SVR3 Environment in integration tests, command
        /// line tools, and examples.
        pub async fn connect_directly(
            &self,
            auth: &Auth,
        ) -> <Self as PpssSetup>::ConnectionResults {
            let endpoints = (self.sgx(), self.nitro(), self.tpm2snp());
            endpoints.connect(auth).await
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use nonzero_ext::nonzero;
    use rand_core::{OsRng, RngCore};

    use super::*;

    fn new_empty_share_set() -> OpaqueMaskedShareSet {
        OpaqueMaskedShareSet {
            inner: SerializableMaskedShareSet {
                server_ids: vec![],
                masked_secret: vec![],
            },
        }
    }

    #[test]
    fn serialized_share_set_has_version() {
        let bytes = new_empty_share_set().serialize().expect("can serialize");
        assert_eq!(MASKED_SHARE_SET_FORMAT, bytes[0]);
    }

    #[test]
    fn deserialize_share_set_supported_version() {
        let there = new_empty_share_set().serialize().expect("can serialize");
        let and_back = OpaqueMaskedShareSet::deserialize(&there);
        assert!(and_back.is_ok(), "Should be able to deserialize");
    }

    #[test]
    fn deserialize_share_set_bad_version() {
        let there = {
            let mut bytes = new_empty_share_set().serialize().expect("can serialize");
            bytes[0] = 0xff;
            bytes
        };
        let and_back = OpaqueMaskedShareSet::deserialize(&there);
        assert!(matches!(
            and_back.expect_err("Unexpected deserialization success"),
            DeserializeError::BadVersion(_),
        ));
    }

    struct TestSvr3Client {
        backup_fn: fn() -> Result<OpaqueMaskedShareSet, Error>,
        restore_fn: fn() -> Result<EvaluationResult, Error>,
        remove_fn: fn() -> Result<(), Error>,
    }

    impl Default for TestSvr3Client {
        fn default() -> Self {
            Self {
                backup_fn: || panic!("Unexpected call to backup"),
                restore_fn: || panic!("Unexpected call to restore"),
                remove_fn: || panic!("Unexpected call to remove"),
            }
        }
    }

    #[async_trait]
    impl Backup for TestSvr3Client {
        async fn backup(
            &self,
            _password: &str,
            _secret: [u8; 32],
            _max_tries: NonZeroU32,
            _rng: &mut (impl CryptoRngCore + Send),
        ) -> Result<OpaqueMaskedShareSet, Error> {
            (self.backup_fn)()
        }
    }

    #[async_trait]
    impl Remove for TestSvr3Client {
        async fn remove(&self) -> Result<(), Error> {
            (self.remove_fn)()
        }
    }

    #[async_trait]
    impl Restore for TestSvr3Client {
        async fn restore(
            &self,
            _password: &str,
            _share_set: OpaqueMaskedShareSet,
            _rng: &mut (impl CryptoRngCore + Send),
        ) -> Result<EvaluationResult, Error> {
            (self.restore_fn)()
        }
    }

    #[async_trait]
    impl Query for TestSvr3Client {
        async fn query(&self) -> Result<u32, Error> {
            unreachable!()
        }
    }

    fn test_evaluation_result() -> EvaluationResult {
        EvaluationResult {
            value: [0; 32],
            tries_remaining: 42,
        }
    }

    fn make_secret() -> [u8; 32] {
        let mut rng = OsRng;
        let mut secret = [0; 32];
        rng.fill_bytes(&mut secret);
        secret
    }

    #[tokio::test]
    async fn restore_with_fallback_primary_success() {
        let primary = TestSvr3Client {
            restore_fn: || Ok(test_evaluation_result()),
            ..TestSvr3Client::default()
        };
        let fallback = TestSvr3Client {
            restore_fn: || panic!("Must not be called"),
            ..TestSvr3Client::default()
        };

        let mut rng = OsRng;
        let result =
            restore_with_fallback((&primary, &fallback), "", new_empty_share_set(), &mut rng).await;
        assert_matches!(result, Ok(evaluation_result) => assert_eq!(evaluation_result, test_evaluation_result()));
    }

    #[tokio::test]
    async fn restore_with_fallback_primary_fatal_error() {
        let primary = TestSvr3Client {
            restore_fn: || Err(Error::ConnectionTimedOut),
            ..TestSvr3Client::default()
        };
        let fallback = TestSvr3Client {
            restore_fn: || panic!("Must not be called"),
            ..TestSvr3Client::default()
        };

        let mut rng = OsRng;
        let result =
            restore_with_fallback((&primary, &fallback), "", new_empty_share_set(), &mut rng).await;
        assert_matches!(result, Err(Error::ConnectionTimedOut));
    }

    #[tokio::test]
    async fn restore_with_fallback_fallback_error() {
        let primary = TestSvr3Client {
            restore_fn: || Err(Error::DataMissing),
            ..TestSvr3Client::default()
        };
        let fallback = TestSvr3Client {
            restore_fn: || Err(Error::RestoreFailed(31415)),
            ..TestSvr3Client::default()
        };
        let mut rng = OsRng;
        let result =
            restore_with_fallback((&primary, &fallback), "", new_empty_share_set(), &mut rng).await;
        assert_matches!(result, Err(Error::RestoreFailed(31415)));
    }

    #[tokio::test]
    async fn restore_with_fallback_fallback_success() {
        let primary = TestSvr3Client {
            restore_fn: || Err(Error::DataMissing),
            ..TestSvr3Client::default()
        };
        let fallback = TestSvr3Client {
            restore_fn: || Ok(test_evaluation_result()),
            ..TestSvr3Client::default()
        };
        let mut rng = OsRng;
        let result =
            restore_with_fallback((&primary, &fallback), "", new_empty_share_set(), &mut rng).await;
        assert_matches!(result, Ok(evaluation_result) => assert_eq!(evaluation_result, test_evaluation_result()));
    }

    #[tokio::test]
    async fn migrate_backup_write_error() {
        let destination = TestSvr3Client {
            backup_fn: || Err(Error::ConnectionTimedOut),
            ..TestSvr3Client::default()
        };
        let mut rng = OsRng;
        let result = migrate_backup(
            (&TestSvr3Client::default(), &destination),
            "",
            make_secret(),
            nonzero!(42u32),
            &mut rng,
        )
        .await;
        assert_matches!(result, Err(Error::ConnectionTimedOut));
    }

    #[tokio::test]
    async fn migrate_backup_remove_error() {
        let source = TestSvr3Client {
            remove_fn: || Err(Error::Protocol("Anything at all".to_string())),
            ..TestSvr3Client::default()
        };
        let destination = TestSvr3Client {
            backup_fn: || Ok(new_empty_share_set()),
            ..TestSvr3Client::default()
        };
        let mut rng = OsRng;
        let result = migrate_backup(
            (&source, &destination),
            "",
            make_secret(),
            nonzero!(42u32),
            &mut rng,
        )
        .await;
        assert_matches!(result, Ok(_share_set));
    }

    #[tokio::test]
    async fn migrate_backup_remove_success() {
        let source = TestSvr3Client {
            remove_fn: || Ok(()),
            ..TestSvr3Client::default()
        };
        let destination = TestSvr3Client {
            backup_fn: || Ok(new_empty_share_set()),
            ..TestSvr3Client::default()
        };
        let mut rng = OsRng;
        let result = migrate_backup(
            (&source, &destination),
            "",
            make_secret(),
            nonzero!(42u32),
            &mut rng,
        )
        .await;
        assert_matches!(result, Ok(_share_set));
    }
}
