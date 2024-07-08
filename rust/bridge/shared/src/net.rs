//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;
use std::num::{NonZeroU16, NonZeroU32};

use base64::prelude::{Engine, BASE64_STANDARD};
use rand::rngs::OsRng;

use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::Svr3Client;
use libsignal_net::auth::Auth;
use libsignal_net::svr3::{self, OpaqueMaskedShareSet, Svr3Client as _};

pub use libsignal_bridge_types::net::{ConnectionManager, Environment, TokioAsyncContext};

use crate::support::*;
use crate::*;

pub(crate) mod cdsi;
pub(crate) mod chat;
mod tokio;

bridge_handle_fns!(ConnectionManager, clone = false);

#[bridge_fn]
fn ConnectionManager_new(
    environment: AsType<Environment, u8>,
    user_agent: String,
) -> ConnectionManager {
    ConnectionManager::new(environment.into_inner(), user_agent)
}

#[bridge_fn]
fn ConnectionManager_set_proxy(
    connection_manager: &ConnectionManager,
    host: String,
    port: i32,
) -> Result<(), std::io::Error> {
    // We take port as an i32 because Java 'short' is signed and thus can't represent all port
    // numbers, and we want too-large port numbers to be handled the same way as 0.
    let port = u16::try_from(port).ok().and_then(NonZeroU16::new);
    connection_manager.set_proxy(&host, port)
}

#[bridge_fn]
fn ConnectionManager_clear_proxy(connection_manager: &ConnectionManager) {
    connection_manager.clear_proxy();
}

#[bridge_fn(jni = false, ffi = false)]
fn ConnectionManager_set_ipv6_enabled(connection_manager: &ConnectionManager, ipv6_enabled: bool) {
    connection_manager.set_ipv6_enabled(ipv6_enabled)
}

#[bridge_fn]
fn CreateOTP(username: String, secret: &[u8]) -> String {
    Auth::otp(&username, secret, std::time::SystemTime::now())
}

#[bridge_fn]
fn CreateOTPFromBase64(username: String, secret: String) -> String {
    let secret = BASE64_STANDARD.decode(secret).expect("valid base64");
    Auth::otp(&username, &secret, std::time::SystemTime::now())
}

#[bridge_io(TokioAsyncContext)]
async fn Svr3Backup(
    connection_manager: &ConnectionManager,
    secret: Box<[u8]>,
    password: String,
    max_tries: AsType<NonZeroU32, u32>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
) -> Result<Vec<u8>, svr3::Error> {
    let secret = secret
        .as_ref()
        .try_into()
        .expect("can only backup 32 bytes");
    let mut rng = OsRng;
    let client = Svr3Client::new(connection_manager, username, enclave_password);
    let share_set = client
        .backup(&password, secret, max_tries.into_inner(), &mut rng)
        .await?;
    Ok(share_set.serialize().expect("can serialize the share set"))
}

#[bridge_io(TokioAsyncContext)]
async fn Svr3Restore(
    connection_manager: &ConnectionManager,
    password: String,
    share_set: Box<[u8]>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
) -> Result<Vec<u8>, svr3::Error> {
    let mut rng = OsRng;
    let share_set = OpaqueMaskedShareSet::deserialize(&share_set)?;
    let client = Svr3Client::new(connection_manager, username, enclave_password);
    let restored_secret = client.restore(&password, share_set, &mut rng).await?;
    Ok(restored_secret.serialize())
}

#[bridge_io(TokioAsyncContext)]
async fn Svr3Remove(
    connection_manager: &ConnectionManager,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
) -> Result<(), svr3::Error> {
    let client = Svr3Client::new(connection_manager, username, enclave_password);
    client.remove().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use test_case::test_case;

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(env, "test-user-agent".to_string());
    }
}
