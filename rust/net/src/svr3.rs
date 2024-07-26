//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU32;
use std::time::Duration;

use async_trait::async_trait;
use bincode::Options as _;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use libsignal_svr3::{EvaluationResult, MaskedShareSet};

use crate::auth::Auth;
use crate::enclave::{self, EnclaveEndpointConnection, Nitro, PpssSetup, Sgx, Tpm2Snp};
use crate::env::Svr3Env;
use crate::infra::dns::DnsResolver;
use crate::infra::errors::LogSafeDisplay;
use crate::infra::tcp_ssl::DirectConnector;
use crate::infra::ws::{
    AttestedConnectionError, DefaultStream, WebSocketConnectError, WebSocketServiceError,
};
use crate::infra::AsyncDuplexStream;
use crate::svr::SvrConnection;

const MASKED_SHARE_SET_FORMAT: u8 = 0;

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct OpaqueMaskedShareSet {
    inner: SerializableMaskedShareSet,
}

// Non pub version of ppss::MaskedShareSet used for serialization
#[derive(Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
struct SerializableMaskedShareSet {
    server_ids: Vec<u64>,
    masked_shares: Vec<[u8; 32]>,
    commitment: [u8; 32],
}

impl From<MaskedShareSet> for SerializableMaskedShareSet {
    fn from(value: MaskedShareSet) -> Self {
        Self {
            server_ids: value.server_ids,
            masked_shares: value.masked_shares,
            commitment: value.commitment,
        }
    }
}

impl SerializableMaskedShareSet {
    fn into(self) -> MaskedShareSet {
        MaskedShareSet {
            server_ids: self.server_ids,
            masked_shares: self.masked_shares,
            commitment: self.commitment,
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
    fn new(inner: MaskedShareSet) -> Self {
        Self {
            inner: inner.into(),
        }
    }
    fn into_inner(self) -> MaskedShareSet {
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
    Connect(WebSocketConnectError),
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
        use libsignal_svr3::{Error as LogicError, PPSSError};
        match err {
            LogicError::Ppss(PPSSError::InvalidCommitment, tries_remaining) => {
                Self::RestoreFailed(tries_remaining)
            }
            LogicError::BadResponseStatus(libsignal_svr3::ErrorStatus::Missing) => {
                Self::DataMissing
            }
            LogicError::Oprf(_)
            | LogicError::Ppss(_, _)
            | LogicError::BadData
            | LogicError::BadResponse
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
            SvrError::Protocol => Self::Protocol("General SVR protocol error".to_string()),
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

/// High level data operations on instances of `PpssSetup`
///
/// These functions are useful if we ever want to perform multiple operations
/// on the same set of open connections, as opposed to having to connect for
/// each individual operation, as implied by `Svr3Client` trait.
mod ppss_ops {
    use super::{Error, OpaqueMaskedShareSet};

    use crate::enclave::{IntoConnections, PpssSetup};
    use crate::infra::ws::{run_attested_interaction, NextOrClose};
    use crate::infra::AsyncDuplexStream;
    use futures_util::future::try_join_all;
    use libsignal_svr3::{Backup, EvaluationResult, Query, Restore};
    use rand_core::CryptoRngCore;
    use std::num::NonZeroU32;

    pub async fn do_backup<S: AsyncDuplexStream + 'static, Env: PpssSetup<S>>(
        connections: Env::Connections,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error> {
        let server_ids = Env::server_ids();
        let backup = Backup::new(server_ids.as_ref(), password, secret, max_tries, rng)?;
        let mut connections = connections.into_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(&backup.requests)
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let results = try_join_all(futures).await?;
        let addresses = connections.as_ref().iter().map(|c| c.remote_address());
        let responses = collect_responses(results, addresses)?;
        let share_set = backup.finalize(rng, &responses)?;
        Ok(OpaqueMaskedShareSet::new(share_set))
    }

    pub async fn do_restore<S: AsyncDuplexStream + 'static, Env: PpssSetup<S>>(
        connections: Env::Connections,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<EvaluationResult, Error> {
        let restore = Restore::new(password, share_set.into_inner(), rng)?;
        let mut connections = connections.into_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(&restore.requests)
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let results = try_join_all(futures).await?;
        let addresses = connections.as_ref().iter().map(|c| c.remote_address());
        let responses = collect_responses(results, addresses)?;
        Ok(restore.finalize(&responses)?)
    }

    pub async fn do_remove<S: AsyncDuplexStream + 'static, Env: PpssSetup<S>>(
        connections: Env::Connections,
    ) -> Result<(), Error> {
        let requests = std::iter::repeat(libsignal_svr3::make_remove_request());
        let mut connections = connections.into_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(requests)
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let results = try_join_all(futures).await?;
        let addresses = connections.as_ref().iter().map(|c| c.remote_address());
        // RemoveResponse's are empty, safe to ignore as long as they came
        let _responses = collect_responses(results, addresses)?;
        Ok(())
    }

    pub async fn do_query<S: AsyncDuplexStream + 'static, Env: PpssSetup<S>>(
        connections: Env::Connections,
    ) -> Result<u32, Error> {
        let mut connections = connections.into_connections();
        let futures = connections
            .as_mut()
            .iter_mut()
            .zip(Query::requests())
            .map(|(connection, request)| run_attested_interaction(connection, request));
        let results = try_join_all(futures).await?;
        let addresses = connections.as_ref().iter().map(|c| c.remote_address());
        let responses = collect_responses(results, addresses)?;
        Ok(Query::finalize(&responses)?)
    }

    fn collect_responses<'a>(
        results: impl IntoIterator<Item = NextOrClose<Vec<u8>>>,
        addresses: impl IntoIterator<Item = &'a url::Host>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        results
            .into_iter()
            .zip(addresses)
            .map(|(next_or_close, address)| {
                next_or_close.next_or(Error::Protocol(format!("no response from {}", address)))
            })
            .collect()
    }
}

#[async_trait]
pub trait Svr3Client {
    async fn backup(
        &self,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error>;

    async fn restore(
        &self,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<EvaluationResult, Error>;

    async fn remove(&self) -> Result<(), Error>;

    async fn query(&self) -> Result<u32, Error>;
}

#[async_trait]
pub trait Svr3Connect {
    // Stream is needed for the blanket implementation,
    // otherwise S would be an unconstrained generic parameter.
    type Stream;
    type Env: PpssSetup<Self::Stream>;
    async fn connect(
        &self,
    ) -> Result<<Self::Env as PpssSetup<Self::Stream>>::Connections, enclave::Error>;
}

#[async_trait]
impl<T> Svr3Client for T
where
    T: Svr3Connect + Sync,
    T::Stream: AsyncDuplexStream + 'static,
{
    async fn backup(
        &self,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error> {
        ppss_ops::do_backup::<T::Stream, T::Env>(
            self.connect().await?,
            password,
            secret,
            max_tries,
            rng,
        )
        .await
    }

    async fn restore(
        &self,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<EvaluationResult, Error> {
        ppss_ops::do_restore::<T::Stream, T::Env>(self.connect().await?, password, share_set, rng)
            .await
    }

    async fn remove(&self) -> Result<(), Error> {
        ppss_ops::do_remove::<T::Stream, T::Env>(self.connect().await?).await
    }

    async fn query(&self) -> Result<u32, Error> {
        ppss_ops::do_query::<T::Stream, T::Env>(self.connect().await?).await
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
    clients: (Primary, Fallback),
    password: &str,
    share_set: OpaqueMaskedShareSet,
    rng: &mut (impl CryptoRngCore + Send),
) -> Result<EvaluationResult, Error>
where
    Primary: Svr3Client + Sync,
    Fallback: Svr3Client + Sync,
{
    let (primary_conn, fallback_conn) = clients;

    match primary_conn.restore(password, share_set.clone(), rng).await {
        Err(Error::DataMissing) => {}
        result @ (Err(_) | Ok(_)) => return result,
    }
    fallback_conn.restore(password, share_set, rng).await
}

/// Move the backup from `From` to `To`, representing current and next SVR3
/// environments, respectively.
///
/// Despite the name, no data is _read_ from `From`, and instead must be
/// provided by the caller just like for an ordinary `backup` call.
///
/// Moving includes _attempting_ deletion from `From` that can fail, in which
/// case the error will be ignored. The other alternative implementations could
/// be:
/// - Do not attempt deleting from `From`.
///   This would leave the data for harvesting longer than necessary, even
///   though the migration period is expected to be relatively short, and the
///   set of `From` enclaves would have been deleted in the end.
/// - Ignore the successful write to `To`.
///   Despite sounding like a better option, it would make `restore_with_fallback`
///   more complicated, as the data may have been written to `To`, thus
///   rendering it impossible to be used for all restores unconditionally.
pub async fn migrate_backup<From, To>(
    clients: (From, To),
    password: &str,
    secret: [u8; 32],
    max_tries: NonZeroU32,
    rng: &mut (impl CryptoRngCore + Send),
) -> Result<OpaqueMaskedShareSet, Error>
where
    From: Svr3Client + Sync,
    To: Svr3Client + Sync,
{
    let (from_client, to_client) = clients;
    let share_set = to_client.backup(password, secret, max_tries, rng).await?;
    let _ = from_client.remove().await;
    Ok(share_set)
}

/// Simplest way to connect to an SVR3 Environment in integration tests, command
/// line tools, and examples.
pub async fn simple_svr3_connect(
    env: &Svr3Env<'static>,
    auth: &Auth,
) -> Result<<Svr3Env<'static> as PpssSetup<DefaultStream>>::Connections, enclave::Error> {
    let connector = DirectConnector::new(DnsResolver::default());
    let sgx_connection = EnclaveEndpointConnection::new(env.sgx(), Duration::from_secs(10));
    let a =
        SvrConnection::<Sgx, _>::connect(auth.clone(), &sgx_connection, connector.clone()).await?;

    let nitro_connection = EnclaveEndpointConnection::new(env.nitro(), Duration::from_secs(10));
    let b = SvrConnection::<Nitro, _>::connect(auth.clone(), &nitro_connection, connector.clone())
        .await?;

    let tpm2snp_connection = EnclaveEndpointConnection::new(env.tpm2snp(), Duration::from_secs(10));
    let c =
        SvrConnection::<Tpm2Snp, _>::connect(auth.clone(), &tpm2snp_connection, connector).await?;

    Ok((a, b, c))
}

#[cfg(test)]
mod test {
    use super::*;

    use assert_matches::assert_matches;
    use nonzero_ext::nonzero;
    use rand_core::{OsRng, RngCore};

    fn new_empty_share_set() -> OpaqueMaskedShareSet {
        OpaqueMaskedShareSet {
            inner: SerializableMaskedShareSet {
                server_ids: vec![],
                masked_shares: vec![],
                commitment: [0; 32],
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
    impl Svr3Client for TestSvr3Client {
        async fn backup(
            &self,
            _password: &str,
            _secret: [u8; 32],
            _max_tries: NonZeroU32,
            _rng: &mut (impl CryptoRngCore + Send),
        ) -> Result<OpaqueMaskedShareSet, Error> {
            (self.backup_fn)()
        }

        async fn restore(
            &self,
            _password: &str,
            _share_set: OpaqueMaskedShareSet,
            _rng: &mut (impl CryptoRngCore + Send),
        ) -> Result<EvaluationResult, Error> {
            (self.restore_fn)()
        }

        async fn remove(&self) -> Result<(), Error> {
            (self.remove_fn)()
        }

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
            restore_with_fallback((primary, fallback), "", new_empty_share_set(), &mut rng).await;
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
            restore_with_fallback((primary, fallback), "", new_empty_share_set(), &mut rng).await;
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
            restore_with_fallback((primary, fallback), "", new_empty_share_set(), &mut rng).await;
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
            restore_with_fallback((primary, fallback), "", new_empty_share_set(), &mut rng).await;
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
            (TestSvr3Client::default(), destination),
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
            (source, destination),
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
            (source, destination),
            "",
            make_secret(),
            nonzero!(42u32),
            &mut rng,
        )
        .await;
        assert_matches!(result, Ok(_share_set));
    }
}
