//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use base64::prelude::{Engine as _, BASE64_STANDARD};
use std::future::Future;
use std::time::Duration;

/// Constructs the value of the `Authorization` header for the `Basic` auth scheme.
pub(crate) fn basic_authorization(username: &str, password: &str) -> String {
    let auth = BASE64_STANDARD.encode(format!("{}:{}", username, password).as_bytes());
    let auth = format!("Basic {}", auth);
    auth
}

/// Requires a `Future` to complete before the specified duration has elapsed.
///
/// Takes in a future whose return type is `Result<T, E>`, a `duration` timeout,
/// and a `timeout_error` of type `E`. Internally, a [tokio::time::timeout] is called,
/// but the return type of this method is the same as the return type of the given `future`,
/// i.e. `Result<T, E>`, which in the case of timing out will be `Err(timeout_error)`.
pub async fn timeout<T, E, F>(duration: Duration, timeout_error: E, future: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(r) => r,
        Err(_) => Err(timeout_error),
    }
}
