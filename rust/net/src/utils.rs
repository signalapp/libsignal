//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(test)]
pub(crate) fn basic_authorization(username: &str, password: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let auth = STANDARD.encode(format!("{}:{}", username, password).as_bytes());
    let auth = format!("Basic {}", auth);
    auth
}
