//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! An example tool to create and restore a backup forward-secrecy-token using a remote SVRB.
//!
//! Usage: `./svrb_testing --auth-secret [32-byte base64 secret]`

use std::str::FromStr;

use async_trait::async_trait;
use base64::prelude::{Engine, BASE64_STANDARD};
use clap::Parser as _;
use libsignal_account_keys::{AccountEntropyPool, BackupKey};
use libsignal_net::auth::Auth;
use libsignal_net::enclave::PpssSetup;
use libsignal_net::env::SvrBEnv;
use libsignal_net::svrb;
use libsignal_net::svrb::direct::direct_connect;
use libsignal_net::svrb::traits::*;
use libsignal_net_infra::testutil::no_network_change_events;
use rand::rngs::OsRng;
use rand::TryRngCore;

#[derive(clap::Parser)]
struct Args {
    #[arg(long, env = "AUTH_SECRET")]
    auth_secret: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Make requests to prod environment"
    )]
    prod: bool,
    #[arg(
        long,
        default_value_t = 1,
        help = "Number of parallel requests to make"
    )]
    parallelism: usize,
    #[arg(long, default_value_t = 1, help = "Number of total requests to make")]
    requests: usize,
}

struct SvrBClient<'a> {
    auth: Auth,
    env: &'a SvrBEnv<'static>,
}

#[async_trait]
impl SvrBConnect for SvrBClient<'_> {
    type Env = SvrBEnv<'static>;

    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults {
        direct_connect(self.env.sgx(), &self.auth, &no_network_change_events()).await
    }
}

async fn single_request(args: &Args, auth_secret: [u8; 32], sem: &tokio::sync::Semaphore) {
    let _guard = sem.acquire().await.unwrap();
    let mut rng = OsRng.unwrap_err();
    let mut uid = [0u8; 16];
    rng.try_fill_bytes(&mut uid)
        .expect("should have entropy available");
    let auth = Auth::from_uid_and_secret(uid, auth_secret);

    let env = if args.prod {
        &libsignal_net::env::PROD.svr_b
    } else {
        &libsignal_net::env::STAGING.svr_b
    };
    let client = SvrBClient { auth, env };

    let aep = AccountEntropyPool::from_str(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("should create AEP");
    let backup_key = BackupKey::derive_from_account_entropy_pool(&aep);

    println!("--- Happy-path test, single key ---");

    // Example code for the first backup ever created by a client.
    // Note that we use `create_new_backup_chain` for the previous_backup_data.
    println!("Storing backup #1");
    let inital_data = svrb::create_new_backup_chain(&client, &backup_key);
    let backup1 = svrb::store_backup(&client, &backup_key, inital_data.as_ref())
        .await
        .expect("should backup");

    // Example code for restoration of the backup.
    println!("Restoring backup #1");
    let restored = svrb::restore_backup(&client, &backup_key, backup1.metadata.as_ref())
        .await
        .expect("should restore successfully");
    assert_eq!(
        restored.forward_secrecy_token.0,
        backup1.forward_secrecy_token.0
    );

    // Example code for second and subsequent backups.  Note that we pass
    // in the previous backup's `next_backup_data`.
    println!("Storing backup #2");
    let backup2 = svrb::store_backup(&client, &backup_key, backup1.next_backup_data.as_ref())
        .await
        .expect("should store");

    // Example code for restoring both backups after storage of backup 2.
    println!("Restoring backup #1 after storing backup #2");
    let restored = svrb::restore_backup(&client, &backup_key, backup1.metadata.as_ref())
        .await
        .expect("should restore successfully");
    assert_eq!(
        restored.forward_secrecy_token.0,
        backup1.forward_secrecy_token.0
    );
    println!("Restoring backup #2 after storing backup #2");
    let restored = svrb::restore_backup(&client, &backup_key, backup2.metadata.as_ref())
        .await
        .expect("should restore successfully");
    assert_eq!(
        restored.forward_secrecy_token.0,
        backup2.forward_secrecy_token.0
    );

    println!("Success!");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let args = Args::parse();
    println!(
        "Running {} requests {} at a time",
        args.requests, args.parallelism
    );
    let sem = tokio::sync::Semaphore::new(args.parallelism);

    let auth_secret: [u8; 32] = {
        BASE64_STANDARD
            .decode(&args.auth_secret)
            .expect("valid b64")
            .try_into()
            .expect("secret is 32 bytes")
    };
    let mut v = vec![];
    for _i in 0..args.requests {
        v.push(single_request(&args, auth_secret, &sem));
    }
    futures::future::join_all(v).await;
}
