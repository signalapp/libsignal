use criterion::{criterion_group, criterion_main, Criterion};
use libsignal_protocol_rust::*;

#[path = "../tests/support/mod.rs"]
mod support;

pub fn session_encrypt_decrypt_result(c: &mut Criterion) -> Result<(), SignalProtocolError> {
    let (alice_session, bob_session) = support::initialize_sessions_v3()?;
    let alice_session_record = SessionRecord::new(alice_session);
    let bob_session_record = SessionRecord::new(bob_session);

    let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1);
    let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1);

    let mut alice_store = support::test_in_memory_protocol_store();
    let mut bob_store = support::test_in_memory_protocol_store();

    alice_store.store_session(&bob_address, &alice_session_record)?;
    bob_store.store_session(&alice_address, &bob_session_record)?;

    let message_to_decrypt = support::encrypt(
                &mut alice_store,
                &bob_address,
                "a short message")?;

    c.bench_function("session encrypt", |b| {
        b.iter(|| {
            let mut alice_store = alice_store.clone();
            support::encrypt(
                &mut alice_store,
                &bob_address,
                "a short message").expect("success");
        })});

    c.bench_function("session decrypt", |b| {
        b.iter(|| {
            let mut bob_store = bob_store.clone();
            support::decrypt(
                &mut bob_store,
                &alice_address,
                &message_to_decrypt).expect("success");
        })});

    Ok(())
}

pub fn session_encrypt_decrypt(mut c: &mut Criterion) {
    session_encrypt_decrypt_result(&mut c).expect("success");
}

criterion_group!(benches, session_encrypt_decrypt);

criterion_main!(benches);
