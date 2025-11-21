//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::ops::Deref;
use std::time::SystemTime;

use hmac::{Hmac, Mac};
use libsignal_net_infra::AsStaticHttpHeader;
use libsignal_net_infra::utils::basic_authorization;
use sha2::Sha256;

/// Generic username/password combination.
///
/// When returned by the chat server's /auth endpoints,
/// - username is a "hex(uid)"
/// - password is a "timestamp:hex(otp(uid, timestamp, secret))"
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(any(test, feature = "test-util"), derive(Default))]
pub struct Auth<S = String> {
    pub username: S,
    pub password: S,
}

impl Auth {
    pub fn from_uid_and_secret(uid: [u8; 16], secret: [u8; 32]) -> Self {
        let username = hex::encode(uid);
        let password = Self::otp(&username, &secret, SystemTime::now());
        Self { username, password }
    }

    const OTP_LEN: usize = 20;
    pub fn otp(username: &str, secret: &[u8], now: SystemTime) -> String {
        let ts = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("not be used with times in the past")
            .as_secs();

        let mac_input = format!("{}:{}", &username, ts);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret).expect("HMAC can take key of any size");
        mac.update(mac_input.as_bytes());

        let digest = mac.finalize().into_bytes();
        let mut khex = hex::encode(digest);
        khex.truncate(Self::OTP_LEN);
        format!("{ts}:{khex}")
    }
}

impl<S: Deref<Target = str>> AsStaticHttpHeader for Auth<S> {
    const HEADER_NAME: http::HeaderName = http::header::AUTHORIZATION;
    fn header_value(&self) -> http::HeaderValue {
        let Self { username, password } = self;
        basic_authorization(username, password)
    }
}
