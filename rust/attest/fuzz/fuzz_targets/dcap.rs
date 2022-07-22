//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::convert::{TryFrom, TryInto};
use std::time::{Duration, SystemTime};

fuzz_target!(
    |input: (&[u8], &[u8], attest::dcap::MREnclave, Vec<String>, i16)| {
        let mut timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1656000000);
        if input.4 >= 0 {
            timestamp += Duration::from_secs(24 * 60 * 60 * u64::try_from(input.4).unwrap());
        } else {
            // watch out for i16::MIN!
            timestamp -=
                Duration::from_secs((-24 * 60 * 60 * i64::from(input.4)).try_into().unwrap());
        }
        let advisory_ids: Vec<&str> = input.3.iter().map(String::as_ref).collect();
        let _ = attest::dcap::verify_remote_attestation(
            input.0,
            input.1,
            &input.2,
            &advisory_ids,
            timestamp,
        );
    }
);
