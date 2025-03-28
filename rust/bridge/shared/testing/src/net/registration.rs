//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;
use std::time::Duration;

use libsignal_bridge_macros::*;
use libsignal_net::registration::{RegistrationSession, RequestedInformation};

use crate::*;

#[bridge_fn(ffi = false, jni = false)]
pub fn TESTING_RegistrationSessionInfoConvert() -> RegistrationSession {
    RegistrationSession {
        allowed_to_request_code: true,
        verified: true,
        next_call: Some(Duration::from_secs(123)),
        next_sms: Some(Duration::from_secs(456)),
        next_verification_attempt: Some(Duration::from_secs(789)),
        requested_information: HashSet::from([RequestedInformation::PushChallenge]),
    }
}
