//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use futures::executor::block_on;
use libsignal_protocol::*;
use std::convert::TryFrom;

#[path = "../tests/support/mod.rs"]
mod support;

pub fn ratchet_forward_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let mut group = c.benchmark_group("ratchet");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10); //minimum allowed...
    group.warm_up_time(core::time::Duration::from_millis(100));

    let mut csprng = rand::rngs::OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1);
    let group_sender =
        SenderKeyName::new("summer camp planning committee".to_owned(), sender_address)?;

    let mut alice_store = support::test_in_memory_protocol_store();
    let mut bob_store = support::test_in_memory_protocol_store();

    let sent_distribution_message = block_on(create_sender_key_distribution_message(
        &group_sender,
        &mut alice_store,
        &mut csprng,
        None,
    ))?;

    let recv_distribution_message =
        SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized()).unwrap();

    block_on(process_sender_key_distribution_message(
        &group_sender,
        &recv_distribution_message,
        &mut bob_store,
        None,
    ))?;

    for ratchets in [100, 1000].iter() {
        let ratchets = *ratchets;

        for i in 0..ratchets {
            block_on(group_encrypt(
                &mut alice_store,
                &group_sender,
                format!("nefarious plotting {}", i).as_bytes(),
                &mut csprng,
                None,
            ))?;
        }

        let alice_ciphertext = block_on(group_encrypt(
            &mut alice_store,
            &group_sender,
            "you got the plan?".as_bytes(),
            &mut csprng,
            None,
        ))?;

        group.bench_function(format!("ratchet {}", ratchets), |b| {
            b.iter(|| {
                let mut bob_store = bob_store.clone();
                block_on(group_decrypt(
                    &alice_ciphertext,
                    &mut bob_store,
                    &group_sender,
                    None,
                ))
                .expect("ok");
            })
        });
    }

    Ok(())
}

pub fn ratchet_forward(mut c: &mut Criterion) {
    ratchet_forward_result(&mut c).expect("success");
}

criterion_group!(ratchet, ratchet_forward);

criterion_main!(ratchet);
