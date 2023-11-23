//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_cross_version_testing::*;

// Use this function to debug tests
#[allow(dead_code)]
fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
        .try_init();
}

fn try_all_combinations(
    f: fn(&mut dyn LibSignalProtocolStore, &mut dyn LibSignalProtocolStore),
    make_previous: &[fn() -> Box<dyn LibSignalProtocolStore>],
) {
    let run = |alice_store: &mut dyn LibSignalProtocolStore,
               bob_store: &mut dyn LibSignalProtocolStore| {
        log::info!(
            "alice: {}, bob: {}",
            alice_store.version(),
            bob_store.version()
        );
        f(alice_store, bob_store)
    };

    // Current<->Current, to test that the test is correct.
    run(
        &mut LibSignalProtocolCurrent::new(),
        &mut LibSignalProtocolCurrent::new(),
    );

    // Current<->Previous
    for bob_store_maker in make_previous {
        let mut alice_store = LibSignalProtocolCurrent::new();
        let mut bob_store = bob_store_maker();
        run(&mut alice_store, &mut *bob_store);
    }

    // Previous<->Current
    for alice_store_maker in make_previous {
        let mut alice_store = alice_store_maker();
        let mut bob_store = LibSignalProtocolCurrent::new();
        run(&mut *alice_store, &mut bob_store);
    }
}

#[test]
fn test_basic_prekey() {
    try_all_combinations(
        run,
        &[
            || Box::new(LibSignalProtocolV21::new()),
            || Box::new(LibSignalProtocolV12::new()),
        ],
    );

    fn run(
        alice_store: &mut dyn LibSignalProtocolStore,
        bob_store: &mut dyn LibSignalProtocolStore,
    ) {
        let alice_name = "alice";
        let bob_name = "bob";

        let bob_pre_key_bundle = bob_store.create_pre_key_bundle();
        alice_store.process_pre_key_bundle(bob_name, bob_pre_key_bundle);

        let original_message = "L'homme est condamné à être libre".as_bytes();
        let (outgoing_message, outgoing_message_type) =
            alice_store.encrypt(bob_name, original_message);
        assert_eq!(outgoing_message_type, CiphertextMessageType::PreKey);

        let ptext = bob_store.decrypt(alice_name, &outgoing_message, outgoing_message_type);
        assert_eq!(&ptext, original_message);

        let bobs_response = "Who watches the watchers?".as_bytes();
        let (bob_outgoing, bob_outgoing_type) = bob_store.encrypt(alice_name, bobs_response);
        assert_eq!(bob_outgoing_type, CiphertextMessageType::Whisper);

        let alice_decrypts = alice_store.decrypt(bob_name, &bob_outgoing, bob_outgoing_type);
        assert_eq!(&alice_decrypts, bobs_response);

        run_interaction(alice_store, alice_name, bob_store, bob_name);
    }
}

fn run_interaction(
    alice_store: &mut dyn LibSignalProtocolStore,
    alice_name: &str,
    bob_store: &mut dyn LibSignalProtocolStore,
    bob_name: &str,
) {
    let alice_ptext = b"It's rabbit season";

    let (alice_message, alice_message_type) = alice_store.encrypt(bob_name, alice_ptext);
    assert_eq!(alice_message_type, CiphertextMessageType::Whisper);
    assert_eq!(
        &bob_store.decrypt(alice_name, &alice_message, alice_message_type),
        alice_ptext
    );

    let bob_ptext = b"It's duck season";

    let (bob_message, bob_message_type) = bob_store.encrypt(alice_name, bob_ptext);
    assert_eq!(bob_message_type, CiphertextMessageType::Whisper);
    assert_eq!(
        &alice_store.decrypt(bob_name, &bob_message, bob_message_type),
        bob_ptext
    );

    for i in 0..10 {
        let alice_ptext = format!("A->B message {}", i);
        let (alice_message, alice_message_type) =
            alice_store.encrypt(bob_name, alice_ptext.as_bytes());
        assert_eq!(alice_message_type, CiphertextMessageType::Whisper);
        assert_eq!(
            &bob_store.decrypt(alice_name, &alice_message, alice_message_type),
            alice_ptext.as_bytes()
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message {}", i);
        let (bob_message, bob_message_type) = bob_store.encrypt(alice_name, bob_ptext.as_bytes());
        assert_eq!(bob_message_type, CiphertextMessageType::Whisper);
        assert_eq!(
            &alice_store.decrypt(bob_name, &bob_message, bob_message_type),
            bob_ptext.as_bytes()
        );
    }

    let mut alice_ooo_messages = vec![];

    for i in 0..10 {
        let alice_ptext = format!("A->B OOO message {}", i);
        let (alice_message, _) = alice_store.encrypt(bob_name, alice_ptext.as_bytes());
        alice_ooo_messages.push((alice_ptext, alice_message));
    }

    for i in 0..10 {
        let alice_ptext = format!("A->B post-OOO message {}", i);
        let (alice_message, _) = alice_store.encrypt(bob_name, alice_ptext.as_bytes());
        assert_eq!(
            &bob_store.decrypt(alice_name, &alice_message, CiphertextMessageType::Whisper),
            alice_ptext.as_bytes()
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message post-OOO {}", i);
        let (bob_message, _) = bob_store.encrypt(alice_name, bob_ptext.as_bytes());
        assert_eq!(
            &alice_store.decrypt(bob_name, &bob_message, CiphertextMessageType::Whisper),
            bob_ptext.as_bytes()
        );
    }

    for (ptext, ctext) in alice_ooo_messages {
        assert_eq!(
            &bob_store.decrypt(alice_name, &ctext, CiphertextMessageType::Whisper),
            ptext.as_bytes()
        );
    }
}
