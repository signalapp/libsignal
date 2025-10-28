//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::{Duration, SystemTime};

use const_str::hex;
use criterion::{Criterion, criterion_group, criterion_main};
use libsignal_keytrans::{
    ChatSearchResponse, DeploymentMode, FullSearchResponse, KeyTransparency, PublicConfig,
    SearchContext, SlimSearchRequest, VerifyingKey, VrfPublicKey,
};
use prost::Message as _;

fn bench_verify_search(c: &mut Criterion) {
    let sig_key = VerifyingKey::from_bytes(&hex!(
        "ac0de1fd7f33552bbeb6ebc12b9d4ea10bf5f025c45073d3fb5f5648955a749e"
    ))
    .unwrap();
    let vrf_key = VrfPublicKey::try_from(hex!(
        "ec3a268237cf5c47115cf222405d5f90cc633ebe05caf82c0dd5acf9d341dadb"
    ))
    .unwrap();
    let auditor_key = VerifyingKey::from_bytes(&hex!(
        "1123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755"
    ))
    .unwrap();
    let aci = uuid::uuid!("90c979fd-eab4-4a08-b6da-69dedeab9b29");
    let request = SlimSearchRequest::new([b"a", aci.as_bytes().as_slice()].concat());

    let ChatSearchResponse {
        tree_head: response_tree_head,
        aci: condensed_response,
        e164: _,
        username_hash: _,
    } = {
        let bytes = include_bytes!("../res/chat_search_response.dat");
        let mut response =
            ChatSearchResponse::decode(bytes.as_slice()).expect("can decode chat response");

        if let Some(head) = response.tree_head.as_mut() {
            // we don't expect these fields to be present in the verification that follows
            head.distinguished = vec![];
            head.last = vec![];
        }

        response
    };
    let response_tree_head = response_tree_head.as_ref().expect("has tree head");
    let response = FullSearchResponse {
        condensed: condensed_response.expect("has ACI condensed response"),
        tree_head: response_tree_head,
    };

    let valid_at = SystemTime::UNIX_EPOCH + include!("../res/chat_response_valid_at.in");

    let kt = KeyTransparency {
        config: PublicConfig {
            mode: DeploymentMode::ThirdPartyAuditing(vec![auditor_key].into()),
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
