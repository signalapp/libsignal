//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! These tests demonstrate both full and partial SVR3 migration.
//! (The tests require a LIBSIGNAL_TESTING_ENCLAVE_SECRET environment variable
//! to be set. Similar to the integration tests of SVR3 APIs in Java, etc. If the
//! variable is not set, the tests will just silently succeed.)
//!
//! Full migration means all three enclaves are being updated, whereas partial
//! only updates <3 enclaves.
//!
//! Partial migration is of a special interest. Let's consider a scenario of
//! migrating only one enclave (SGX in this test). Prev environment will consist
//! of (Sgx, Nitro, Tpm2Snp) enclaves, and the Current one will contain
//! (Sgx', Nitro, Tpm2Snp). Note the "prime" on Sgx. The migration function will
//! first write the data to the Current, and then remove it from the Prev. If
//! done naively, using "whole" environments, it will leave us with only Sgx'
//! surviving with any data, and no chance of ever restoring the secret.
//! This explains the existence of a partial environment. It will be passed into
//! the `migrate_backup` function to guarantee that only the Sgx (no prime) data
//! will be removed during migration.
//!
//! The trick to test any migration with only one actual SVR3 environment is to
//! utilize the fact that user-id is an implicit argument to all the SVR3
//! operations. Thus, `Env::STAGING.Svr3 + UID1` and `Env::STAGING.Svr3 + UID2`
//! will effectively be two different, non-overlapping, environments.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use assert_matches::assert_matches;
use async_trait::async_trait;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use libsignal_net::auth::Auth;
use libsignal_net::enclave::{EnclaveEndpoint, EnclaveKind, Error, PpssSetup, Sgx};
use libsignal_net::env::Svr3Env;
use libsignal_net::infra::tcp_ssl::DirectConnector;
use libsignal_net::infra::TransportConnector;
use libsignal_net::svr::SvrConnection;
use libsignal_net::svr3::direct::DirectConnect;
use libsignal_net::svr3::traits::*;
use libsignal_net::svr3::{migrate_backup, restore_with_fallback, OpaqueMaskedShareSet};
use libsignal_svr3::EvaluationResult;
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng};

const PASS: &str = "password";
const TRIES: NonZeroU32 = nonzero!(10u32);

const PREV_ENV: Svr3Env = libsignal_net::env::STAGING.svr3;
const REM_ENV: SingletonEnv<'static, Sgx> = SingletonEnv(PREV_ENV.sgx());

type Stream = <DirectConnector as TransportConnector>::Stream;

#[derive(Clone)]
struct FullClient {
    auth: Auth,
}

#[async_trait]
impl Svr3Connect for FullClient {
    type Stream = Stream;
    type Env = Svr3Env<'static>;

    async fn connect(&self) -> <Self::Env as PpssSetup<Self::Stream>>::ConnectionResults {
        PREV_ENV.connect_directly(&self.auth).await
    }
}

#[derive(Clone)]
struct PartialClient {
    auth: Auth,
}

/// Single-enclave environment. Allows to connect to each of the SVR3 enclaves individually.
struct SingletonEnv<'a, E: EnclaveKind>(&'a EnclaveEndpoint<'a, E>);

// This will be our "removing" setup.
impl<S: Send> PpssSetup<S> for SingletonEnv<'_, Sgx> {
    type Stream = S;
    type ConnectionResults = Result<SvrConnection<Sgx, S>, Error>;
    type ServerIds = [u64; 1];

    fn server_ids() -> Self::ServerIds {
        [1]
    }
}

#[async_trait]
impl Svr3Connect for PartialClient {
    type Stream = Stream;
    type Env = SingletonEnv<'static, Sgx>;

    async fn connect(&self) -> <Self::Env as PpssSetup<Self::Stream>>::ConnectionResults {
        REM_ENV.0.connect(&self.auth).await
    }
}

#[derive(Clone)]
struct ValidatingClient<T> {
    inner: T,
    backup_calls: Arc<AtomicUsize>,
    restore_calls: Arc<AtomicUsize>,
    query_calls: Arc<AtomicUsize>,
    remove_calls: Arc<AtomicUsize>,
}

impl<T> ValidatingClient<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            backup_calls: Arc::default(),
            restore_calls: Arc::default(),
            query_calls: Arc::default(),
            remove_calls: Arc::default(),
        }
    }

    fn backup_calls(&self) -> usize {
        self.backup_calls.load(Ordering::Relaxed)
    }

    fn restore_calls(&self) -> usize {
        self.restore_calls.load(Ordering::Relaxed)
    }

    fn query_calls(&self) -> usize {
        self.query_calls.load(Ordering::Relaxed)
    }

    fn remove_calls(&self) -> usize {
        self.remove_calls.load(Ordering::Relaxed)
    }

    // This is to simplify assertions
    // Counters are in the same order as fields: (backup, restore, query, remove)
    fn get_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.backup_calls(),
            self.restore_calls(),
            self.query_calls(),
            self.remove_calls(),
        )
    }
}

#[async_trait]
impl<T: Backup + Sync + Send> Backup for ValidatingClient<T> {
    async fn backup(
        &self,
        password: &str,
        secret: [u8; 32],
        max_tries: NonZeroU32,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, libsignal_net::svr3::Error> {
        self.backup_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.backup(password, secret, max_tries, rng).await
    }
}

#[async_trait]
impl<T: Restore + Sync + Send> Restore for ValidatingClient<T> {
    async fn restore(
        &self,
        password: &str,
        share_set: OpaqueMaskedShareSet,
        rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<EvaluationResult, libsignal_net::svr3::Error> {
        self.restore_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.restore(password, share_set, rng).await
    }
}

#[async_trait]
impl<T: Query + Sync + Send> Query for ValidatingClient<T> {
    async fn query(&self) -> Result<u32, libsignal_net::svr3::Error> {
        self.query_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.query().await
    }
}

#[async_trait]
impl<T: Remove + Sync + Send> Remove for ValidatingClient<T> {
    async fn remove(&self) -> Result<(), libsignal_net::svr3::Error> {
        self.remove_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.remove().await
    }
}

#[tokio::test]
async fn svr3_single_enclave_migration() {
    init_logger();

    let Some(enclave_secret) = get_enclave_secret() else {
        log::info!(
            "LIBSIGNAL_TESTING_ENCLAVE_SECRET environment variable is not set. The test will be ignored."
        );
        return;
    };

    let mut rng = OsRng;

    let secret = random_bytes(&mut rng);
    log::info!("Secret to be stored: {}", &hex::encode(secret));

    log::info!("Creating clients...");
    let prev_uid = random_bytes(&mut rng);
    let prev_auth = Auth::from_uid_and_secret(prev_uid, enclave_secret);
    let prev_client = ValidatingClient::new(FullClient {
        auth: prev_auth.clone(),
    });

    let current_uid = random_bytes(&mut rng);
    let current_auth = Auth::from_uid_and_secret(current_uid, enclave_secret);
    let current_client = ValidatingClient::new(FullClient { auth: current_auth });

    assert_ne!(&prev_uid, &current_uid);

    let removing_client = ValidatingClient::new(PartialClient { auth: prev_auth });
    log::info!("DONE");

    log::info!("Writing the initial backup...");
    let share_set = prev_client
        .backup(PASS, secret, TRIES, &mut rng)
        .await
        .expect("can backup");
    log::info!("DONE");

    log::info!("Validating the initial backup...");
    let restored = restore_with_fallback(
        (&current_client, &prev_client),
        PASS,
        share_set.clone(),
        &mut rng,
    )
    .await
    .expect("can restore");
    assert_eq!(&restored.value, &secret);
    log::info!("OK");

    log::info!("Checking the current environment pre-migration...");
    assert_matches!(
        current_client.query().await,
        Err(libsignal_net::svr3::Error::DataMissing)
    );
    log::info!("DONE");

    log::info!("Checking the previous sgx pre-migration...");
    // Removing client refers to the Sgx part of the "previous" environment.
    // So there should be data there.
    removing_client
        .clone()
        .query()
        .await
        .expect("Prev SGX should have data");
    log::info!("DONE");

    log::info!("Migrating...");
    let new_share_set = migrate_backup(
        (&removing_client, &current_client),
        PASS,
        secret,
        TRIES,
        &mut rng,
    )
    .await
    .expect("can migrate");

    log::info!("DONE");

    log::info!("Validating the final state...");
    log::info!("- Data should be gone from the prev sgx");
    assert_matches!(
        removing_client.query().await,
        Err(libsignal_net::svr3::Error::DataMissing)
    );
    log::info!("- Query/restore from prev env should fail with DataMissing");
    assert_matches!(
        prev_client.query().await,
        Err(libsignal_net::svr3::Error::DataMissing)
    );

    log::info!("- Can restore from the current env with the right remaining_tries");
    let restored = restore_with_fallback(
        (&current_client, &prev_client),
        PASS,
        new_share_set.clone(),
        &mut rng,
    )
    .await
    .expect("can restore after migration");
    assert_eq!(restored.tries_remaining, TRIES.get() - 1);
    assert_eq!(&restored.value, &secret);

    assert_eq!((1, 1, 1, 0), prev_client.get_counts());
    assert_eq!((1, 2, 1, 0), current_client.get_counts());
    assert_eq!((0, 0, 2, 1), removing_client.get_counts());

    log::info!("OK");

    log::info!("Cleaning up...");
    let _ = prev_client.remove().await;
    let _ = current_client.remove().await;
    log::info!("DONE");
}

#[tokio::test]
async fn svr3_full_migration() {
    init_logger();

    let Some(enclave_secret) = get_enclave_secret() else {
        log::info!(
            "LIBSIGNAL_TESTING_ENCLAVE_SECRET environment variable is not set. The test will be ignored."
        );
        return;
    };
    let mut rng = OsRng;

    let secret = random_bytes(&mut rng);
    log::info!("Secret to be stored: {}", &hex::encode(secret));

    log::info!("Creating clients...");
    let prev_uid = random_bytes(&mut rng);
    let prev_auth = Auth::from_uid_and_secret(prev_uid, enclave_secret);
    let prev_client = FullClient {
        auth: prev_auth.clone(),
    };

    let current_uid = random_bytes(&mut rng);
    let current_auth = Auth::from_uid_and_secret(current_uid, enclave_secret);
    let current_client = FullClient { auth: current_auth };

    assert_ne!(&prev_uid, &current_uid);
    log::info!("DONE");

    log::info!("Writing the initial backup...");
    let share_set = prev_client
        .backup(PASS, secret, TRIES, &mut rng)
        .await
        .expect("can backup");
    log::info!("DONE");

    log::info!("Validating the initial backup...");
    let restored = prev_client
        .restore(PASS, share_set.clone(), &mut rng)
        .await
        .expect("can restore");
    assert_eq!(&restored.value, &secret);
    log::info!("OK");

    log::info!("Checking the current environment pre-migration...");
    assert_matches!(
        current_client.query().await,
        Err(libsignal_net::svr3::Error::DataMissing)
    );
    log::info!("DONE");

    log::info!("Migrating...");
    let new_share_set = migrate_backup(
        (&prev_client, &current_client),
        PASS,
        secret,
        TRIES,
        &mut rng,
    )
    .await
    .expect("can migrate");
    log::info!("DONE");

    log::info!("Validating the final state...");
    log::info!("- Query/restore from prev env should fail with DataMissing");
    assert_matches!(
        prev_client.query().await,
        Err(libsignal_net::svr3::Error::DataMissing)
    );

    log::info!("- Can restore from the current env with the right remaining_tries");
    let restored = current_client
        .restore(PASS, new_share_set.clone(), &mut rng)
        .await
        .expect("can restore after migration");
    assert_eq!(restored.tries_remaining, TRIES.get() - 1);
    assert_eq!(&restored.value, &secret);
    log::info!("OK");

    log::info!("Cleaning up...");
    let _ = current_client.remove().await;
    log::info!("DONE");
}

fn random_bytes<const N: usize>(rng: &mut impl CryptoRngCore) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes[..]);
    bytes
}

fn parse_auth_secret(b64: &str) -> [u8; 32] {
    BASE64_STANDARD
        .decode(b64)
        .expect("valid b64")
        .try_into()
        .expect("secret is 32 bytes")
}

fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn get_enclave_secret() -> Option<[u8; 32]> {
    std::env::var("LIBSIGNAL_TESTING_ENCLAVE_SECRET")
        .map(|b64| parse_auth_secret(&b64))
        .ok()
}
