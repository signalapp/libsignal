//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use libfuzzer_sys::fuzz_target;
use libsignal_protocol::*;

fuzz_target!(|data: &[u8]| {
    let _: Result<_, _> = SealedSenderV2SentMessage::parse(data);
});
