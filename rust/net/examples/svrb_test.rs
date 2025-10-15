//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! An example tool to create and restore a backup forward-secrecy-token using a remote SVRB.
//!
//! Usage: `./svrb_testing --auth-secret [32-byte base64 secret]`

use std::str::FromStr;
use std::time::SystemTime;

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine};
use clap::Parser as _;
use hex::ToHex as _;
use libsignal_account_keys::{AccountEntropyPool, BackupKey};
use libsignal_net::auth::Auth;
use libsignal_net::enclave::PpssSetup;
use libsignal_net::env::SvrBEnv;
use libsignal_net::svrb;
use libsignal_net::svrb::direct::direct_connect;
use libsignal_net::svrb::traits::*;
use libsignal_net_infra::utils::no_network_change_events;
use rand::TryRngCore;
use rand::rngs::OsRng;

#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    username: Option<String>,
    #[arg(long, default_value = "")]
    password: String,
    #[arg(long, env = "AUTH_SECRET", conflicts_with = "password", value_parser = parse_auth_secret)]
    auth_secret: Option<[u8; 32]>,
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

#[derive(Clone, Copy)]
struct SvrBClient<'a> {
    auth: &'a Auth,
    env: &'a SvrBEnv<'static>,
}

#[async_trait]
impl SvrBConnect for SvrBClient<'_> {
    type Env = SvrBEnv<'static>;

    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults {
        direct_connect(
            self.env
                .current()
                .next()
                .expect("should have at least one current SVRB instance"),
            self.auth,
            &no_network_change_events(),
        )
        .await
    }
}

async fn single_request(args: &Args, sem: &tokio::sync::Semaphore) {
    let _guard = sem.acquire().await.unwrap();
    let mut rng = OsRng.unwrap_err();

    let username = if let Some(username) = args.username.clone() {
        username
    } else {
        // Generate a random SVR username, rather than a static one.
        let mut uid = [0u8; 16];
        rng.try_fill_bytes(&mut uid)
            .expect("should have entropy available");
        uid.encode_hex()
    };

    let password = if let Some(auth_secret) = args.auth_secret {
        Auth::otp(&username, &auth_secret, SystemTime::now())
    } else {
        args.password.clone()
    };
    let auth = Auth { username, password };

    let env = if args.prod {
        &libsignal_net::env::PROD.svr_b
    } else {
        &libsignal_net::env::STAGING.svr_b
    };
    let client = SvrBClient { auth: &auth, env };

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
    let backup1 =
        svrb::store_backup::<_, SvrBClient>(&[client], &[], &backup_key, inital_data.as_ref())
            .await
            .expect("should backup");

    // Example code for restoration of the backup.
    println!("Restoring backup #1");
    let restored = svrb::restore_backup(&[client], &backup_key, backup1.metadata.as_ref())
        .await
        .expect("should restore successfully");
    assert_eq!(
        restored.forward_secrecy_token.0,
        backup1.forward_secrecy_token.0
    );

    // Example code for second and subsequent backups.  Note that we pass
    // in the previous backup's `next_backup_data`.
    println!("Storing backup #2");
    let backup2 = svrb::store_backup::<_, SvrBClient>(
        &[client],
        &[],
        &backup_key,
        backup1.next_backup_data.as_ref(),
    )
    .await
    .expect("should store");

    // Example code for restoring both backups after storage of backup 2.
    println!("Restoring backup #1 after storing backup #2");
    let restored = svrb::restore_backup(&[client], &backup_key, backup1.metadata.as_ref())
        .await
        .expect("should restore successfully");
    assert_eq!(
        restored.forward_secrecy_token.0,
        backup1.forward_secrecy_token.0
    );
    println!("Restoring backup #2 after storing backup #2");
    let restored = svrb::restore_backup(&[client], &backup_key, backup2.metadata.as_ref())
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
    env_logger::init();

    let args = Args::parse();
    println!(
        "Running {} requests {} at a time",
        args.requests, args.parallelism
    );
    let sem = tokio::sync::Semaphore::new(args.parallelism);

    let mut v = vec![];
    for _i in 0..args.requests {
        v.push(single_request(&args, &sem));
    }
    futures::future::join_all(v).await;
}

fn parse_auth_secret(input: &str) -> Result<[u8; 32], base64::DecodeError> {
    BASE64_STANDARD
        .decode(input)?
        .try_into()
        .map_err(|_| base64::DecodeError::InvalidLength(input.len()))
}
