//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::{Duration, SystemTime};

use criterion::{criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use libsignal_keytrans::{
    DeploymentMode, KeyTransparency, PublicConfig, SearchContext, SearchResponse,
    SlimSearchRequest, VerifyingKey, VrfPublicKey,
};
use prost::Message as _;

fn bench_verify_search(c: &mut Criterion) {
    let sig_key = VerifyingKey::from_bytes(&hex!(
        "12a21ad60d5a3978e19a3b0baa8c35c55a20e10d45f39e5cb34bf6e1b3cce432"
    ))
    .unwrap();
    let vrf_key = VrfPublicKey::try_from(hex!(
        "1e71563470c1b8a6e0aadf280b6aa96f8ad064674e69b80292ee46d1ab655fcf"
    ))
    .unwrap();
    let auditor_key = VerifyingKey::from_bytes(&hex!(
        "1123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755"
    ))
    .unwrap();
    let aci = uuid::uuid!("84fd7196-b3fa-4d4d-bbf8-8f1cdf2b7cea");
    let request = SlimSearchRequest {
        search_key: [b"a", aci.as_bytes().as_slice()].concat(),
        version: None,
    };
    let response = {
        let bytes = include_bytes!("../res/kt-search-response.dat");
        SearchResponse::decode(bytes.as_slice()).unwrap()
    };
    let valid_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1724279958);
    let kt = KeyTransparency {
        config: PublicConfig {
            mode: DeploymentMode::ThirdPartyAuditing(auditor_key),
            signature_key: sig_key,
            vrf_key,
        },
    };

    c.bench_function("verify_search_internal", |b| {
        b.iter(|| {
            std::hint::black_box(
                kt.verify_search(
                    request.clone(),
                    response.clone(),
                    SearchContext::default(),
                    true,
                    valid_at,
                )
                .expect("should succeed"),
            );
        });
    });
}

criterion_group!(benches, bench_verify_search);
criterion_main!(benches);
