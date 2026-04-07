//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use assert_matches::assert_matches;
use libsignal_protocol_cross_version_testing::*;

#[test]
fn test_alice_lacks_spqr() {
    let alice_name = "alice";
    let bob_name = "bob";
    let mut alice_store = Box::new(LibSignalProtocolV73::new());
    let mut bob_store = Box::new(LibSignalProtocolCurrent::new());

    let bob_pre_key_bundle = bob_store.create_pre_key_bundle();
    alice_store.process_pre_key_bundle(bob_name, bob_pre_key_bundle);

    let original_message = "L'homme est condamné à être libre".as_bytes();
    let (outgoing_message, outgoing_message_type) =
        alice_store.encrypt(bob_name, alice_name, original_message);

    let err = bob_store
        .decrypt(
            alice_name,
            bob_name,
            &outgoing_message,
            outgoing_message_type,
        )
        .expect_err("decryption should fail");
    assert_matches!(
        *err.downcast::<libsignal_protocol_current::SignalProtocolError>()
            .expect("unexpected error type"),
        libsignal_protocol_current::SignalProtocolError::InvalidMessage(
            libsignal_protocol_current::CiphertextMessageType::PreKey,
            "decryption failed"
        )
    );
}

#[test]
fn test_bob_lacks_spqr() {
    let alice_name = "alice";
    let bob_name = "bob";
    let mut alice_store = Box::new(LibSignalProtocolCurrent::new());
    let mut bob_store = Box::new(LibSignalProtocolV73::new());

    let bob_pre_key_bundle = bob_store.create_pre_key_bundle();
    alice_store.process_pre_key_bundle(bob_name, bob_pre_key_bundle);

    let original_message = "L'homme est condamné à être libre".as_bytes();
    let (outgoing_message, outgoing_message_type) =
        alice_store.encrypt(bob_name, alice_name, original_message);

    let err = bob_store
        .decrypt(
            alice_name,
            bob_name,
            &outgoing_message,
            outgoing_message_type,
        )
        .expect_err("decryption should fail");
    assert_matches!(
        *err.downcast::<libsignal_protocol_v73::SignalProtocolError>()
            .expect("unexpected error type"),
        libsignal_protocol_v73::SignalProtocolError::InvalidMessage(
            libsignal_protocol_v73::CiphertextMessageType::PreKey,
            "decryption failed"
        )
    );
}
