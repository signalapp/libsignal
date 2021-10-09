//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use criterion::{criterion_group, criterion_main, Criterion};
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;

#[path = "../tests/support/mod.rs"]
mod support;

pub fn session_encrypt_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let (alice_session_record, bob_session_record) = support::initialize_sessions_v3()?;

    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    let mut alice_store = support::test_in_memory_protocol_store()?;
    let mut bob_store = support::test_in_memory_protocol_store()?;

    alice_store
        .store_session(&bob_address, &alice_session_record, None)
        .now_or_never()
        .expect("sync")?;
    bob_store
        .store_session(&alice_address, &bob_session_record, None)
        .now_or_never()
        .expect("sync")?;

    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session decrypt first message", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    let _ = support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
        .now_or_never()
        .expect("sync")?;
    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session encrypt", |b| {
        b.iter(|| {
            support::encrypt(&mut alice_store, &bob_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });
    c.bench_function("session decrypt", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    // Archive on Alice's side...
    let mut state = alice_store
        .load_session(&bob_address, None)
        .now_or_never()
        .expect("sync")?
        .expect("already decrypted successfully");
    state.archive_current_state()?;
    alice_store
        .store_session(&bob_address, &state, None)
        .now_or_never()
        .expect("sync")?;

    // ...then initialize a new session...
    let bob_signed_pre_key_pair = KeyPair::generate(&mut OsRng);

    let bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key.serialize();
    let bob_signed_pre_key_signature = bob_store
        .get_identity_key_pair(None)
        .now_or_never()
        .expect("sync")?
        .private_key()
        .calculate_signature(&bob_signed_pre_key_public, &mut OsRng)?;

    let signed_pre_key_id = 22;

    let bob_pre_key_bundle = PreKeyBundle::new(
        bob_store
            .get_local_registration_id(None)
            .now_or_never()
            .expect("sync")?,
        1.into(),                 // device id
        None,                     // pre key
        signed_pre_key_id.into(), // signed pre key id
        bob_signed_pre_key_pair.public_key,
        bob_signed_pre_key_signature.to_vec(),
        *bob_store
            .get_identity_key_pair(None)
            .now_or_never()
            .expect("sync")?
            .identity_key(),
    )?;

    bob_store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                /*timestamp*/ 42,
                &bob_signed_pre_key_pair,
                &bob_signed_pre_key_signature,
            ),
            None,
        )
        .now_or_never()
        .expect("sync")?;

    // initialize_sessions_v3 makes up its own identity keys,
    // so we need to reset here to avoid it looking like the identity changed.
    alice_store.identity_store.reset();
    bob_store.identity_store.reset();

    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_pre_key_bundle,
        &mut OsRng,
        None,
    )
    .now_or_never()
    .expect("sync")?;

    let original_message_to_decrypt = message_to_decrypt;

    // ...send another message to archive on Bob's side...
    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;
    let _ = support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
        .now_or_never()
        .expect("sync")?;
    // ...and prepare another message to benchmark decrypting.
    let message_to_decrypt = support::encrypt(&mut alice_store, &bob_address, "a short message")
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session decrypt with archived state", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    // Reset once more to go back to the original message.
    bob_store.identity_store.reset();

    c.bench_function("session decrypt using previous state", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(&mut bob_store, &alice_address, &original_message_to_decrypt)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    Ok(())
}

pub fn session_encrypt_decrypt_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let (alice_session_record, bob_session_record) = support::initialize_sessions_v3()?;

    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

    let mut alice_store = support::test_in_memory_protocol_store()?;
    let mut bob_store = support::test_in_memory_protocol_store()?;

    alice_store
        .store_session(&bob_address, &alice_session_record, None)
        .now_or_never()
        .expect("sync")?;
    bob_store
        .store_session(&alice_address, &bob_session_record, None)
        .now_or_never()
        .expect("sync")?;

    c.bench_function("session encrypt+decrypt 1 way", |b| {
        b.iter(|| {
            let ctext = support::encrypt(&mut alice_store, &bob_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
            let _ptext = support::decrypt(&mut bob_store, &alice_address, &ctext)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    c.bench_function("session encrypt+decrypt ping pong", |b| {
        b.iter(|| {
            let ctext = support::encrypt(&mut alice_store, &bob_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
            let _ptext = support::decrypt(&mut bob_store, &alice_address, &ctext)
                .now_or_never()
                .expect("sync")
                .expect("success");

            let ctext = support::encrypt(&mut bob_store, &alice_address, "a short message")
                .now_or_never()
                .expect("sync")
                .expect("success");
            let _ptext = support::decrypt(&mut alice_store, &bob_address, &ctext)
                .now_or_never()
                .expect("sync")
                .expect("success");
        })
    });

    Ok(())
}

pub fn session_encrypt(c: &mut Criterion) {
    session_encrypt_result(c).expect("success");
}

pub fn session_encrypt_decrypt(c: &mut Criterion) {
    session_encrypt_decrypt_result(c).expect("success");
}

criterion_group!(benches, session_encrypt, session_encrypt_decrypt);

criterion_main!(benches);
