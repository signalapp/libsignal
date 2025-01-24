//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;

use base64::prelude::{Engine, BASE64_STANDARD};
use libsignal_bridge_macros::bridge_fn;
pub use libsignal_bridge_types::net::{ConnectionManager, Environment, TokioAsyncContext};
use libsignal_net::auth::Auth;
use libsignal_net::chat::ConnectionInfo;

use crate::support::*;
use crate::*;

pub(crate) mod cdsi;
pub(crate) mod chat;
mod keytrans;
mod tokio;

bridge_handle_fns!(ConnectionInfo, clone = false, jni = false);

bridge_handle_fns!(ConnectionManager, clone = false);

#[bridge_fn]
fn ConnectionManager_new(
    environment: AsType<Environment, u8>,
    user_agent: String,
) -> ConnectionManager {
    ConnectionManager::new(environment.into_inner(), user_agent.as_str())
}

#[bridge_fn]
fn ConnectionManager_set_proxy(
    connection_manager: &ConnectionManager,
    scheme: String,
    host: String,
    port: i32,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), std::io::Error> {
    // We take port as an i32 because Java 'short' is signed and thus can't represent all port
    // numbers, and we want too-large port numbers to be handled the same way as 0. However, we
    // *also* want to have a representation that means "no port provided". We'll use something
    // unlikely for anyone to have typed manually, especially in decimal: `i32::MIN`. (We're not
    // using 0 as the placeholder because an explicitly-specified zero should be diagnosed as
    // invalid.) Note that we also *don't* return early from this function if the port is invalid;
    // that should poison the connection manager. See [`ConnectionManager::set_proxy`].
    let port: Option<Result<NonZeroU16, i32>> = if port == i32::MIN {
        None
    } else {
        Some(
            u16::try_from(port)
                .ok()
                .and_then(NonZeroU16::new)
                .ok_or(port),
        )
    };
    connection_manager.set_proxy(&scheme, &host, port, username, password)
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
fn ConnectionManager_set_censorship_circumvention_enabled(
    connection_manager: &ConnectionManager,
    enabled: bool,
) {
    connection_manager.set_censorship_circumvention_enabled(enabled)
}

#[bridge_fn]
fn ConnectionManager_on_network_change(connection_manager: &ConnectionManager) {
    connection_manager.on_network_change()
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

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(env, "test-user-agent");
    }
}
