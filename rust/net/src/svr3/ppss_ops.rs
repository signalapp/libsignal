//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! High level data operations on instances of `PpssSetup`
//!
//! These functions are useful if we ever want to perform multiple operations
//! on the same set of open connections, as opposed to having to connect for
//! each individual operation, as implied by `Svr3Client` trait.
use super::{Error, OpaqueMaskedShareSet};

use crate::enclave::{IntoConnections, PpssSetup};
use crate::infra::ws::{run_attested_interaction, NextOrClose};
use crate::infra::AsyncDuplexStream;
use futures_util::future::join_all;
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
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let addresses = connections.as_ref().iter().map(|c| c.remote_address());
    let responses = collect_responses(results?, addresses)?;
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
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let addresses = connections.as_ref().iter().map(|c| c.remote_address());
    let responses = collect_responses(results?, addresses)?;
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
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let addresses = connections.as_ref().iter().map(|c| c.remote_address());
    // RemoveResponse's are empty, safe to ignore as long as they came
    let _responses = collect_responses(results?, addresses)?;
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
    let results = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
    let addresses = connections.as_ref().iter().map(|c| c.remote_address());
    let responses = collect_responses(results?, addresses)?;
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
