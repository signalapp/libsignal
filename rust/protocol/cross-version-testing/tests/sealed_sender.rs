//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_cross_version_testing::*;
use libsignal_protocol_current::{
    ContentHint, DeviceId, KeyPair, SealedSenderV2SentMessage, SenderCertificate,
    ServerCertificate, Timestamp,
};
use rand::rng;

const BOB_UUID: uuid::Uuid = uuid::uuid!("b000000b-6199-486a-ba89-2ba2bb4f2154");

fn make_alice_sender_cert(alice_store: &mut dyn LibSignalProtocolStore) -> SenderCertificate {
    let fake_trust_root = KeyPair::generate(&mut rng());
    let signer_key = KeyPair::generate(&mut rng());
    let server_cert = ServerCertificate::new(
        0xfa75e,
        signer_key.public_key,
        &fake_trust_root.private_key,
        &mut rng(),
    )
    .expect("valid");
    let identity_key = *alice_store
        .create_pre_key_bundle()
        .identity_key()
        .expect("has identity key");
    SenderCertificate::new(
        "alice".to_owned(),
        Some("+16505550101".to_owned()),
        *identity_key.public_key(),
        DeviceId::new(1).expect("valid"),
        Timestamp::from_epoch_millis(0),
        server_cert,
        &signer_key.private_key,
        &mut rng(),
    )
    .expect("valid")
}

fn assert_eq_usmc(
    original: &UnidentifiedSenderMessageContent,
    decrypted: &UnidentifiedSenderMessageContent,
) {
    // Check the fields rather than just re-serializing to make sure the protobuf definition hasn't
    // changed either. But we also re-serialize in case a field is added that's not checked here.
    assert_eq!(
        original.msg_type().expect("has field"),
        decrypted.msg_type().expect("has field")
    );
    assert_eq!(
        original.contents().expect("has field"),
        decrypted.contents().expect("has field")
    );
    assert_eq!(
        original.group_id().expect("has field"),
        decrypted.group_id().expect("has field")
    );
    assert_eq!(
        original.content_hint().expect("has field"),
        decrypted.content_hint().expect("has field")
    );
    assert_eq!(
        original
            .sender()
            .expect("has field")
            .serialized()
            .expect("can serialize"),
        decrypted
            .sender()
            .expect("has field")
            .serialized()
            .expect("can serialize"),
    );
    assert_eq!(
        original.serialized().expect("can serialize the whole USMC"),
        decrypted
            .serialized()
            .expect("can serialize the whole USMC"),
    );
}

#[test]
fn ssv1() {
    try_all_combinations(run, &[|| Box::new(LibSignalProtocolV70::new())]);

    fn run(
        alice_store: &mut dyn LibSignalProtocolStore,
        bob_store: &mut dyn LibSignalProtocolStore,
    ) {
        alice_store
            .process_pre_key_bundle(&BOB_UUID.to_string(), bob_store.create_pre_key_bundle());

        let message = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            make_alice_sender_cert(alice_store),
            b"payload".to_vec(),
            ContentHint::Resendable,
            Some(b"group".to_vec()),
        )
        .expect("valid");

        let encrypted = alice_store.encrypt_sealed_sender_v1(&BOB_UUID.to_string(), &message);
        let decrypted = bob_store.decrypt_sealed_sender(&encrypted);

        assert_eq_usmc(&message, &decrypted);
    }
}

#[test]
fn ssv2() {
    try_all_combinations(run, &[|| Box::new(LibSignalProtocolV70::new())]);

    fn run(
        alice_store: &mut dyn LibSignalProtocolStore,
        bob_store: &mut dyn LibSignalProtocolStore,
    ) {
        alice_store
            .process_pre_key_bundle(&BOB_UUID.to_string(), bob_store.create_pre_key_bundle());

        let message = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            make_alice_sender_cert(alice_store),
            b"payload".to_vec(),
            ContentHint::Resendable,
            Some(b"group".to_vec()),
        )
        .expect("valid");

        let encrypted_to_send =
            alice_store.encrypt_sealed_sender_v2(&BOB_UUID.to_string(), &message);

        let parsed_encrypted_to_send =
            SealedSenderV2SentMessage::parse(&encrypted_to_send).expect("valid");
        assert_eq!(1, parsed_encrypted_to_send.recipients.len());
        let encrypted_to_receive = parsed_encrypted_to_send
            .received_message_parts_for_recipient(&parsed_encrypted_to_send.recipients[0])
            .as_ref()
            .concat();

        let decrypted = bob_store.decrypt_sealed_sender(&encrypted_to_receive);

        assert_eq_usmc(&message, &decrypted);
    }
}
