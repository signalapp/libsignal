//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::*;

mod support;
use rand::TryRngCore as _;
use support::*;

#[test]
fn test_alice_and_bob_agree_on_chain_keys_with_kyber() -> Result<(), SignalProtocolError> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();

    let alice_identity_key_pair = IdentityKeyPair::generate(&mut csprng);
    let alice_base_key_pair = KeyPair::generate(&mut csprng);

    let bob_ephemeral_key_pair = KeyPair::generate(&mut csprng);
    let bob_identity_key_pair = IdentityKeyPair::generate(&mut csprng);
    let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

    let bob_kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);

    let alice_parameters = AliceSignalProtocolParameters::new(
        alice_identity_key_pair,
        alice_base_key_pair,
        *bob_identity_key_pair.identity_key(),
        bob_signed_pre_key_pair.public_key,
        bob_ephemeral_key_pair.public_key,
        bob_kyber_pre_key_pair.public_key.clone(),
        UsePQRatchet::Yes,
    );

    let alice_record = initialize_alice_session_record(&alice_parameters, &mut csprng)?;

    assert_eq!(
        KYBER_AWARE_MESSAGE_VERSION,
        alice_record.session_version().expect("must have a version")
    );

    let kyber_ciphertext = alice_record
        .get_kyber_ciphertext()
        .expect("must have session")
        .expect("must have kyber ciphertext")
        .clone()
        .into_boxed_slice();

    let bob_parameters = BobSignalProtocolParameters::new(
        bob_identity_key_pair,
        bob_signed_pre_key_pair,
        None,
        bob_ephemeral_key_pair,
        bob_kyber_pre_key_pair,
        *alice_identity_key_pair.identity_key(),
        alice_base_key_pair.public_key,
        &kyber_ciphertext,
        UsePQRatchet::Yes,
    );
    let bob_record = initialize_bob_session_record(&bob_parameters)?;

    assert_eq!(
        KYBER_AWARE_MESSAGE_VERSION,
        bob_record.session_version().expect("must have a version")
    );

    assert_eq!(
        bob_record
            .get_sender_chain_key_bytes()
            .expect("alice should have chain key"),
        alice_record
            .get_receiver_chain_key_bytes(&bob_ephemeral_key_pair.public_key)
            .expect("should have chain key")
            .expect("")
            .to_vec()
    );

    Ok(())
}
