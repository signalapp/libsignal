//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! High level data operations on instances of `PpssSetup`
//!
//! These functions are useful if we ever want to perform multiple operations
//! on the same set of open connections, as opposed to having to connect for
//! each individual operation, as implied by `Svr3Client` trait.
use std::collections::VecDeque;
use std::num::NonZeroU32;

use futures_util::future::join_all;
use rand_core::CryptoRngCore;

use libsignal_svr3::{make_remove_request, Backup, EvaluationResult, Query, Restore};

use crate::enclave::{ArrayIsh, IntoConnectionResults, PpssSetup};
use crate::infra::ws::{run_attested_interaction, AttestedConnection, NextOrClose};
use crate::infra::AsyncDuplexStream;

use super::{Error, OpaqueMaskedShareSet};

pub async fn do_backup<S: AsyncDuplexStream + 'static, Env: PpssSetup<S>>(
    connect_results: Env::ConnectionResults,
    password: &str,
    secret: [u8; 32],
    max_tries: NonZeroU32,
    rng: &mut (impl CryptoRngCore + Send),
) -> Result<OpaqueMaskedShareSet, Error> {
    let ConnectionContext {
        mut connections,
        addresses,
        mut errors,
    } = ConnectionContext::new(connect_results);
    if let Some(err) = errors.pop_front() {
        return Err(err);
    }

    let server_ids = Env::server_ids();
    let backup = Backup::new(server_ids.as_ref(), password, secret, max_tries, rng)?;
    let futures = connections
        .iter_mut()
        .zip(&backup.requests)
        .map(|(connection, request)| run_attested_interaction(connection, request));
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let responses = collect_responses(results?, addresses.iter())?;
    let share_set = backup.finalize(rng, &responses)?;
    Ok(OpaqueMaskedShareSet::new(share_set))
}

pub async fn do_restore<S: AsyncDuplexStream + 'static>(
    connect_results: impl IntoConnectionResults<Stream = S>,
    password: &str,
    share_set: OpaqueMaskedShareSet,
    rng: &mut (impl CryptoRngCore + Send),
) -> Result<EvaluationResult, Error> {
    let ConnectionContext {
        mut connections,
        addresses,
        mut errors,
    } = ConnectionContext::new(connect_results);
    if let Some(err) = errors.pop_front() {
        return Err(err);
    }

    let restore = Restore::new(password, share_set.into_inner(), rng)?;
    let futures = connections
        .iter_mut()
        .zip(&restore.requests)
        .map(|(connection, request)| run_attested_interaction(connection, request));
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let responses = collect_responses(results?, addresses.iter())?;
    Ok(restore.finalize(&responses)?)
}

pub async fn do_remove<S: AsyncDuplexStream + 'static>(
    connect_results: impl IntoConnectionResults<Stream = S>,
) -> Result<(), Error> {
    let ConnectionContext {
        mut connections,
        addresses,
        errors,
    } = ConnectionContext::new(connect_results);
    for err in errors {
        // For the remove operation we ignore connection failures
        // and proceed to work with the successful connections.
        log::debug!("Connection failure '{:?}' will be ignored.", &err);
    }
    let futures = connections
        .iter_mut()
        .map(|connection| run_attested_interaction(connection, make_remove_request()));
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let _responses = collect_responses(results?, addresses.iter())?;
    Ok(())
}

pub async fn do_query<S: AsyncDuplexStream + 'static>(
    connect_results: impl IntoConnectionResults<Stream = S>,
) -> Result<u32, Error> {
    let ConnectionContext {
        mut connections,
        addresses,
        mut errors,
    } = ConnectionContext::new(connect_results);
    if let Some(err) = errors.pop_front() {
        return Err(err);
    }

    let futures = connections
        .iter_mut()
        .zip(Query::requests())
        .map(|(connection, request)| run_attested_interaction(connection, request));
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let responses = collect_responses(results?, addresses.iter())?;
    Ok(Query::finalize(&responses)?)
}

struct ConnectionContext<S> {
    connections: Vec<AttestedConnection<S>>,
    addresses: Vec<url::Host>,
    errors: VecDeque<Error>,
}

impl<S: AsyncDuplexStream + 'static> ConnectionContext<S> {
    fn new<Arr: IntoConnectionResults<Stream = S>>(connect_results: Arr) -> Self {
        let mut connections = Vec::with_capacity(Arr::ConnectionResults::N);
        let mut addresses = Vec::with_capacity(Arr::ConnectionResults::N);
        let mut errors = VecDeque::with_capacity(Arr::ConnectionResults::N);
        for connect_result in connect_results.into_connection_results().into_iter() {
            match connect_result {
                Ok(connection) => {
                    addresses.push(connection.remote_address().clone());
                    connections.push(connection);
                }
                Err(err) => errors.push_back(err.into()),
            }
        }
        Self {
            connections,
            addresses,
            errors,
        }
    }
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

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use nonzero_ext::nonzero;
    use rand_core::OsRng;

    use attest::nitro::NitroError;

    use crate::enclave::Error;
    use crate::infra::ws::DefaultStream;

    use super::*;

    struct TestEnv;

    impl PpssSetup<DefaultStream> for TestEnv {
        type Stream = DefaultStream;
        type ConnectionResults = NotConnectedResults;
        type ServerIds = [u64; 2];

        fn server_ids() -> Self::ServerIds {
            [1, 2]
        }
    }

    struct NotConnectedResults;

    impl IntoConnectionResults for NotConnectedResults {
        type Stream = DefaultStream;
        type ConnectionResults = [Result<AttestedConnection<DefaultStream>, Error>; 2];

        fn into_connection_results(self) -> Self::ConnectionResults {
            [
                Err(Error::ConnectionTimedOut),
                Err(Error::AttestationError(NitroError::InvalidCbor.into())),
            ]
        }
    }

    #[tokio::test]
    async fn do_backup_fails_with_the_first_error() {
        let mut rng = OsRng;
        let result = do_backup::<DefaultStream, TestEnv>(
            NotConnectedResults,
            "",
            [0; 32],
            nonzero!(1u32),
            &mut rng,
        )
        .await;
        assert_matches!(result, Err(crate::svr3::Error::ConnectionTimedOut));
    }

    #[tokio::test]
    async fn do_restore_fails_with_the_first_error() {
        let mut rng = OsRng;
        let result = do_restore(
            NotConnectedResults,
            "",
            OpaqueMaskedShareSet::default(),
            &mut rng,
        )
        .await;
        assert_matches!(result, Err(crate::svr3::Error::ConnectionTimedOut));
    }

    #[tokio::test]
    async fn do_query_fails_with_the_first_error() {
        let result = do_query(NotConnectedResults).await;
        assert_matches!(result, Err(crate::svr3::Error::ConnectionTimedOut));
    }

    #[tokio::test]
    async fn do_remove_does_not_fail_on_bad_connections() {
        do_remove(NotConnectedResults)
            .await
            .expect("Should ignore connection errors");
    }
}
