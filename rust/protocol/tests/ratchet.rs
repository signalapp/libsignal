//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hex_literal::hex;
use libsignal_protocol::*;

mod support;
use support::*;

#[test]
fn test_ratcheting_session_as_bob() -> Result<(), SignalProtocolError> {
    let bob_ephemeral_public =
        hex!("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458");

    let bob_ephemeral_private =
        hex!("a1cab48f7c893fafa9880a28c3b4999d28d6329562d27a4ea4e22e9ff1bdd65a");

    let bob_identity_public =
        hex!("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626");

    let bob_identity_private =
        hex!("4875cc69ddf8ea0719ec947d61081135868d5fd801f02c0225e516df2156605e");

    let alice_base_public =
        hex!("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950");

    let alice_identity_public =
        hex!("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a");

    let bob_signed_prekey_public =
        hex!("05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67");

    let bob_signed_prekey_private =
        hex!("583900131fb727998b7803fe6ac22cc591f342e4e42a8c8d5d78194209b8d253");

    let expected_sender_chain = "9797caca53c989bbe229a40ca7727010eb2604fc14945d77958a0aeda088b44d";

    let bob_identity_key_public = IdentityKey::decode(&bob_identity_public)?;

    let bob_identity_key_private = PrivateKey::deserialize(&bob_identity_private)?;

    let bob_identity_key_pair =
        IdentityKeyPair::new(bob_identity_key_public, bob_identity_key_private);

    let bob_ephemeral_pair =
        KeyPair::from_public_and_private(&bob_ephemeral_public, &bob_ephemeral_private)?;

    let bob_signed_prekey_pair =
        KeyPair::from_public_and_private(&bob_signed_prekey_public, &bob_signed_prekey_private)?;

    let alice_base_public_key = PublicKey::deserialize(&alice_base_public)?;

    let bob_parameters = BobSignalProtocolParameters::new(
        bob_identity_key_pair,
        bob_signed_prekey_pair,
        None, // one time pre key pair
        bob_ephemeral_pair,
        None, // kyber pre key pair
        IdentityKey::decode(&alice_identity_public)?,
        alice_base_public_key,
        None, // kyber ciphertext
        None, // ephemeral derivation key
    );

    let bob_record = initialize_bob_session_record(&bob_parameters)?;

    assert_eq!(
        hex::encode(bob_record.local_identity_key_bytes()?),
        hex::encode(bob_identity_public)
    );
    assert_eq!(
        hex::encode(
            bob_record
                .remote_identity_key_bytes()?
                .expect("value exists")
        ),
        hex::encode(alice_identity_public)
    );
    assert_eq!(
        hex::encode(bob_record.get_sender_chain_key_bytes()?),
        expected_sender_chain
    );
    assert_eq!(
        PRE_KYBER_MESSAGE_VERSION,
        bob_record.session_version().expect("must have a version")
    );

    Ok(())
}

#[test]
fn test_ratcheting_session_as_alice() -> Result<(), SignalProtocolError> {
    let bob_ephemeral_public =
        hex!("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458");

    let bob_identity_public =
        hex!("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626");

    let alice_base_public =
        hex!("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950");

    let alice_base_private =
        hex!("11ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449");

    let bob_signed_prekey_public =
        hex!("05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67");

    let alice_identity_public =
        hex!("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a");

    let alice_identity_private =
        hex!("9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58");

    // This differs from the Java test and needs investigation
    let expected_receiver_chain =
        "ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a";

    let alice_identity_key_public = IdentityKey::decode(&alice_identity_public)?;

    let bob_ephemeral_public = PublicKey::deserialize(&bob_ephemeral_public)?;

    let alice_identity_key_private = PrivateKey::deserialize(&alice_identity_private)?;

    let bob_signed_prekey_public = PublicKey::deserialize(&bob_signed_prekey_public)?;

    let alice_identity_key_pair =
        IdentityKeyPair::new(alice_identity_key_public, alice_identity_key_private);

    let alice_base_key = KeyPair::from_public_and_private(&alice_base_public, &alice_base_private)?;

    let alice_parameters = AliceSignalProtocolParameters::new(
        alice_identity_key_pair,
        alice_base_key,
        IdentityKey::decode(&bob_identity_public)?,
        bob_signed_prekey_public,
        bob_ephemeral_public,
    );

    let mut csprng = rand::rngs::OsRng;
    let alice_record = initialize_alice_session_record(&alice_parameters, &mut csprng)?;

    assert_eq!(
        hex::encode(alice_record.local_identity_key_bytes()?),
        hex::encode(alice_identity_public),
    );
    assert_eq!(
        hex::encode(
            alice_record
                .remote_identity_key_bytes()?
                .expect("value exists")
        ),
        hex::encode(bob_identity_public)
    );

    assert_eq!(
        hex::encode(
            alice_record
                .get_receiver_chain_key_bytes(&bob_ephemeral_public)?
                .expect("value exists")
        ),
        expected_receiver_chain
    );
    assert_eq!(
        PRE_KYBER_MESSAGE_VERSION,
        alice_record.session_version().expect("must have a version")
    );

    Ok(())
}

#[test]
fn test_alice_and_bob_agree_on_chain_keys_with_kyber() -> Result<(), SignalProtocolError> {
    let mut csprng = rand::rngs::OsRng;

    let alice_identity_key_pair = IdentityKeyPair::generate(&mut csprng);
    let alice_base_key_pair = KeyPair::generate(&mut csprng);

    let bob_ephemeral_key_pair = KeyPair::generate(&mut csprng);
    let bob_identity_key_pair = IdentityKeyPair::generate(&mut csprng);
    let bob_signed_pre_key_pair = KeyPair::generate(&mut csprng);

    let bob_kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);

    let alice_parameters = AliceSignalProtocolParameters::new(
        alice_identity_key_pair,
        alice_base_key_pair,
        *bob_identity_key_pair.identity_key(),
        bob_signed_pre_key_pair.public_key,
        bob_ephemeral_key_pair.public_key,
    )
    .with_their_kyber_pre_key(&bob_kyber_pre_key_pair.public_key);

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
        Some(bob_kyber_pre_key_pair),
        *alice_identity_key_pair.identity_key(),
        alice_base_key_pair.public_key,
        Some(&kyber_ciphertext),
        None, // ephemeral derivation key
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
