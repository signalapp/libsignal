//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use attest::dcap::*;

#[test]
fn verify_remote_attestation_not_for_production() {
    let expected_pubkey = read_test_file("tests/data/dcap.pubkey");
    let trusted_ca_cert = read_test_file("tests/data/trustedRootCaCert.pem");

    let evidence_bytes = read_test_file("tests/data/dcap.evidence");
    let endorsement_bytes = read_test_file("tests/data/dcap.endorsements");

    let earliest_valid_time = SystemTime::now() - Duration::from_secs(60 * 60 * 24);

    let actual_pubkey = NOT_FOR_PRODUCTION_verify_remote_attestation(
        evidence_bytes.as_slice(),
        endorsement_bytes.as_slice(),
        &[],
        trusted_ca_cert.as_slice(),
        earliest_valid_time,
    )
    .expect("failed to get claims")
    .get("pk")
    .expect("pk claim is missing")
    .clone();

    assert_eq!(expected_pubkey, actual_pubkey);
}

fn read_test_file(path: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).expect("failed to read file")
}
