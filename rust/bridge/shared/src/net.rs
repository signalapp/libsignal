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
use libsignal_net::infra::errors::LogSafeDisplay;
use libsignal_net::infra::route::ConnectionProxyConfig;

use crate::support::*;
use crate::*;

pub(crate) mod cdsi;
pub(crate) mod chat;
mod keytrans;
mod tokio;

bridge_handle_fns!(ConnectionInfo, clone = false, jni = false);

bridge_handle_fns!(ConnectionProxyConfig);

#[bridge_fn]
fn ConnectionProxyConfig_new(
    mut scheme: String,
    host: String,
    port: i32,
    username: Option<String>,
    password: Option<String>,
) -> Result<ConnectionProxyConfig, std::io::Error> {
    // We take port as an i32 because Java 'short' is signed and thus can't represent all port
    // numbers, and we want too-large port numbers to be handled the same way as 0. However, we
    // *also* want to have a representation that means "no port provided". We'll use something
    // unlikely for anyone to have typed manually, especially in decimal: `i32::MIN`. (We're not
    // using 0 as the placeholder because an explicitly-specified zero should be diagnosed as
    // invalid.)
    let port = if port == i32::MIN {
        None
    } else {
        Some(
            u16::try_from(port)
                .ok()
                .and_then(NonZeroU16::new)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid port '{port}'"),
                    )
                })?,
        )
    };

    let auth = match (username, password) {
        (None, None) => None,
        (None, Some(_)) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot have password without username",
            ));
        }
        (Some(username), password) => Some((username, password.unwrap_or_default())),
    };

    // We allow clients to pass in upper or mixed-case schemes, but convert to
    // lowercase for ease of matching.
    scheme.make_ascii_lowercase();

    ConnectionProxyConfig::from_parts(&scheme, &host, port, auth).map_err(|e| {
        use libsignal_net::infra::route::ProxyFromPartsError;
        static_assertions::assert_impl_all!(ProxyFromPartsError: LogSafeDisplay);
        match e {
            ProxyFromPartsError::UnsupportedScheme(_) => {
                std::io::Error::new(std::io::ErrorKind::Unsupported, e.to_string())
            }
            ProxyFromPartsError::MissingHost
            | ProxyFromPartsError::SchemeDoesNotSupportUsernames(_)
            | ProxyFromPartsError::SchemeDoesNotSupportPasswords(_) => {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            }
        }
    })
}

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
    proxy: &ConnectionProxyConfig,
) {
    connection_manager.set_proxy(proxy.clone())
}

#[bridge_fn]
fn ConnectionManager_set_invalid_proxy(connection_manager: &ConnectionManager) {
    connection_manager.set_invalid_proxy()
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
    connection_manager.on_network_change(std::time::Instant::now())
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

#[cfg(any(feature = "node", feature = "jni", feature = "ffi"))]
#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;

    #[test_case("http" => matches ConnectionProxyConfig::Http(_); "lowercase")]
    #[test_case("HTTP" => matches ConnectionProxyConfig::Http(_); "uppercase")]
    #[test_case("HTtp" => matches ConnectionProxyConfig::Http(_); "mixed case")]
    #[test_case("Socks" => matches ConnectionProxyConfig::Socks(_); "capitalized")]
    #[test_case("httpS" => matches ConnectionProxyConfig::Http(_); "reverse capitalized")]

    fn connection_proxy_config_accepts_mixed_case_scheme(scheme: &str) -> ConnectionProxyConfig {
        ConnectionProxyConfig_new(scheme.to_owned(), "host".to_owned(), 80, None, None)
            .expect("valid")
    }
}
