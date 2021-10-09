//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use futures_util::FutureExt;
use libsignal_protocol::*;
use std::convert::TryFrom;
use uuid::Uuid;

#[path = "../tests/support/mod.rs"]
mod support;

pub fn ratchet_forward_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let mut group = c.benchmark_group("ratchet");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10); //minimum allowed...
    group.warm_up_time(core::time::Duration::from_millis(100));

    let mut csprng = rand::rngs::OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
    let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

    let mut alice_store = support::test_in_memory_protocol_store()?;
    let mut bob_store = support::test_in_memory_protocol_store()?;

    let sent_distribution_message = create_sender_key_distribution_message(
        &sender_address,
        distribution_id,
        &mut alice_store,
        &mut csprng,
        None,
    )
    .now_or_never()
    .expect("sync")?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

    process_sender_key_distribution_message(
        &sender_address,
        &recv_distribution_message,
        &mut bob_store,
        None,
    )
    .now_or_never()
    .expect("sync")?;

    for ratchets in [100, 1000].iter() {
        let ratchets = *ratchets;

        for i in 0..ratchets {
            group_encrypt(
                &mut alice_store,
                &sender_address,
                distribution_id,
                format!("nefarious plotting {}", i).as_bytes(),
                &mut csprng,
                None,
            )
            .now_or_never()
            .expect("sync")?;
        }

        let alice_ciphertext = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "you got the plan?".as_bytes(),
            &mut csprng,
            None,
        )
        .now_or_never()
        .expect("sync")?;

        group.bench_function(format!("ratchet {}", ratchets), |b| {
            b.iter(|| {
                let mut bob_store = bob_store.clone();
                group_decrypt(
                    alice_ciphertext.serialized(),
                    &mut bob_store,
                    &sender_address,
                    None,
                )
                .now_or_never()
                .expect("sync")
                .expect("ok");
            })
        });
    }

    Ok(())
}

pub fn ratchet_forward(c: &mut Criterion) {
    ratchet_forward_result(c).expect("success");
}

criterion_group!(ratchet, ratchet_forward);

criterion_main!(ratchet);
