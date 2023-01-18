//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;

use crate::*;
use ::attest::ias;

#[bridge_fn(jni = false, node = false)]
pub fn verify_signature(
    cert_pem: &[u8],
    body: &[u8],
    signature: &[u8],
    current_timestamp: u64,
) -> bool {
    let current_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(current_timestamp);
    match ias::verify_signature(cert_pem, body, signature, current_time) {
        Err(e) => {
            log::warn!("Signature verification failed. Reason: {}", e);
            false
        }
        Ok(_) => true,
    }
}
