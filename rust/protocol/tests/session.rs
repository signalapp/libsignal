//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
mod support;

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

use assert_matches::assert_matches;
use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng, TryRngCore as _};
use support::*;

type TestResult = Result<(), SignalProtocolError>;

// Use this function to debug tests
#[allow(dead_code)]
fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
        .try_init();
}

#[test]
fn test_basic_prekey() -> TestResult {
    run(
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
            builder.add_kyber_pre_key(IdChoice::Next);
        },
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run<F>(bob_add_keys: F, expected_session_version: u32) -> TestResult
    where
        F: Fn(&mut TestStoreBuilder),
    {
        async {
            let mut csprng = OsRng.unwrap_err();
            let established_session_requirements = SessionUsabilityRequirements::all();

            let bob_device_id = DeviceId::new(1).unwrap();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

            let mut bob_store_builder = TestStoreBuilder::new();
            bob_add_keys(&mut bob_store_builder);

            let mut alice_store_builder = TestStoreBuilder::new();
            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            assert!(alice_store.load_session(&bob_address).await?.is_some());
            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            let outgoing_message = encrypt(alice_store, &bob_address, original_message).await?;

            assert_eq!(
                outgoing_message.message_type(),
                CiphertextMessageType::PreKey
            );

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message.serialize())?,
            );

            let ptext = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &incoming_message,
            )
            .await?;

            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );

            let bobs_response = "Who watches the watchers?";

            assert!(
                bob_store_builder
                    .store
                    .load_session(&alice_address)
                    .await?
                    .is_some()
            );
            let bobs_session_with_alice = bob_store_builder
                .store
                .load_session(&alice_address)
                .await?
                .expect("session found");
            assert!(
                bobs_session_with_alice
                    .has_usable_sender_chain(SystemTime::now(), established_session_requirements)
                    .expect("can check usability")
            );
            assert_eq!(
                bobs_session_with_alice.session_version()?,
                expected_session_version
            );
            assert_eq!(bobs_session_with_alice.alice_base_key()?.len(), 32 + 1);

            let bob_outgoing =
                encrypt(&mut bob_store_builder.store, &alice_address, bobs_response).await?;

            assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);

            let alice_decrypts = decrypt(alice_store, &bob_address, &bob_outgoing).await?;

            assert_eq!(
                String::from_utf8(alice_decrypts).expect("valid utf8"),
                bobs_response
            );
            assert!(
                alice_store
                    .load_session(&bob_address)
                    .await?
                    .expect("session found")
                    .has_usable_sender_chain(SystemTime::now(), established_session_requirements)
                    .expect("can check usability")
            );

            run_interaction(
                alice_store,
                &alice_address,
                &mut bob_store_builder.store,
                &bob_address,
            )
            .await?;

            let mut alter_alice_store = TestStoreBuilder::new().store;

            bob_add_keys(&mut bob_store_builder);

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);
            process_prekey_bundle(
                &bob_address,
                &mut alter_alice_store.session_store,
                &mut alter_alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            let outgoing_message =
                encrypt(&mut alter_alice_store, &bob_address, original_message).await?;

            assert!(matches!(
                decrypt(&mut bob_store_builder.store, &alice_address, &outgoing_message)
                    .await
                    .unwrap_err(),
                SignalProtocolError::UntrustedIdentity(a) if a == alice_address
            ));

            assert_eq!(
                bob_store_builder
                    .store
                    .save_identity(
                        &alice_address,
                        alter_alice_store
                            .get_identity_key_pair()
                            .await?
                            .identity_key(),
                    )
                    .await?,
                IdentityChange::ReplacedExisting
            );

            let decrypted = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &outgoing_message,
            )
            .await?;
            assert_eq!(
                String::from_utf8(decrypted).expect("valid utf8"),
                original_message
            );

            // Sign pre-key with wrong key:
            let bad_bob_pre_key_bundle = bob_store_builder
                .make_bundle_with_latest_keys(bob_device_id)
                .modify(|content| {
                    let wrong_identity = alter_alice_store
                        .get_identity_key_pair()
                        .now_or_never()
                        .expect("sync")
                        .expect("has identity key");
                    content.identity_key = Some(*wrong_identity.identity_key());
                })
                .expect("can reconstruct the bundle");

            assert!(
                process_prekey_bundle(
                    &bob_address,
                    &mut alter_alice_store.session_store,
                    &mut alter_alice_store.identity_store,
                    &bad_bob_pre_key_bundle,
                    SystemTime::now(),
                    &mut csprng,
                )
                .await
                .is_err()
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }
    Ok(())
}

#[test]
#[ignore = "slow to run locally"]
fn test_chain_jump_over_limit() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new();
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(31337.into())
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());

    run(&mut alice_store_builder, &mut bob_store_builder)?;
    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            // Same as library consts.rs
            pub const MAX_FORWARD_JUMPS: usize = 25_000;

            for _i in 0..(MAX_FORWARD_JUMPS + 1) {
                let _msg =
                    encrypt(alice_store, &bob_address, "Yet another message for you").await?;
            }

            let too_far = encrypt(alice_store, &bob_address, "Now you have gone too far").await?;

            assert!(
                decrypt(&mut bob_store_builder.store, &alice_address, &too_far,)
                    .await
                    .is_err()
            );
            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
#[ignore = "slow to run locally"]
fn test_chain_jump_over_limit_with_self() -> TestResult {
    let mut store_builder_one = TestStoreBuilder::new();
    let mut store_builder_two = TestStoreBuilder::from_store(&store_builder_one.store)
        .with_pre_key(31337.into())
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());
    run(&mut store_builder_one, &mut store_builder_two)?;

    fn run(
        a1_store_builder: &mut TestStoreBuilder,
        a2_store_builder: &mut TestStoreBuilder,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();

            let device_id_1 = DeviceId::new(1).unwrap();
            let a1_address = ProtocolAddress::new("+14151111111".to_owned(), device_id_1);
            let device_id_2 = DeviceId::new(2).unwrap();
            let a2_address = ProtocolAddress::new("+14151111111".to_owned(), device_id_2);

            let a1_store = &mut a1_store_builder.store;

            let a2_pre_key_bundle = a2_store_builder.make_bundle_with_latest_keys(device_id_2);

            process_prekey_bundle(
                &a2_address,
                &mut a1_store.session_store,
                &mut a1_store.identity_store,
                &a2_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            // Same as library consts.rs
            pub const MAX_FORWARD_JUMPS: usize = 25_000;

            for _i in 0..(MAX_FORWARD_JUMPS + 1) {
                let _msg =
                    encrypt(a1_store, &a2_address, "Yet another message for yourself").await?;
            }

            let too_far =
                encrypt(a1_store, &a2_address, "This is the song that never ends").await?;

            let ptext = decrypt(&mut a2_store_builder.store, &a1_address, &too_far).await?;
            assert_eq!(
                String::from_utf8(ptext).unwrap(),
                "This is the song that never ends"
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_bad_signed_pre_key_signature() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();
        let bob_address =
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

        let mut alice_store = TestStoreBuilder::new().store;
        let bob_store_builder = TestStoreBuilder::new()
            .with_pre_key(31337.into())
            .with_signed_pre_key(22.into())
            .with_kyber_pre_key(8000.into());

        let good_bundle = bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

        for bit in 0..8 * good_bundle
            .signed_pre_key_signature()
            .expect("has signature")
            .len()
        {
            let mut bad_signature = good_bundle
                .signed_pre_key_signature()
                .expect("has signature")
                .to_vec();

            bad_signature[bit / 8] ^= 0x01u8 << (bit % 8);

            let bad_bundle = good_bundle
                .clone()
                .modify(|content| content.signed_pre_key_signature = Some(bad_signature))
                .expect("can recreate the bundle");

            assert!(
                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bad_bundle,
                    SystemTime::now(),
                    &mut csprng,
                )
                .await
                .is_err()
            );
        }

        // Finally check that the non-corrupted signature is accepted:
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &good_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_repeat_bundle_message() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new();
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(3133.into())
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
        expected_session_version: u32,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();
            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            assert!(alice_store.load_session(&bob_address).await?.is_some());
            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            let outgoing_message1 = encrypt(alice_store, &bob_address, original_message).await?;
            let outgoing_message2 = encrypt(alice_store, &bob_address, original_message).await?;

            assert_eq!(
                outgoing_message1.message_type(),
                CiphertextMessageType::PreKey
            );
            assert_eq!(
                outgoing_message2.message_type(),
                CiphertextMessageType::PreKey
            );

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message1.serialize())?,
            );

            let ptext = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &incoming_message,
            )
            .await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );

            let bob_outgoing = encrypt(
                &mut bob_store_builder.store,
                &alice_address,
                original_message,
            )
            .await?;
            assert_eq!(bob_outgoing.message_type(), CiphertextMessageType::Whisper);
            let alice_decrypts = decrypt(alice_store, &bob_address, &bob_outgoing).await?;
            assert_eq!(
                String::from_utf8(alice_decrypts).expect("valid utf8"),
                original_message
            );

            // The test

            let incoming_message2 = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message2.serialize())?,
            );

            let ptext = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &incoming_message2,
            )
            .await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );

            let bob_outgoing = encrypt(
                &mut bob_store_builder.store,
                &alice_address,
                original_message,
            )
            .await?;
            let alice_decrypts = decrypt(alice_store, &bob_address, &bob_outgoing).await?;
            assert_eq!(
                String::from_utf8(alice_decrypts).expect("valid utf8"),
                original_message
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_bad_message_bundle() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new();
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(3133.into())
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
        expected_session_version: u32,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());
            let pre_key_id = bob_pre_key_bundle.pre_key_id()?.expect("has pre key id");

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            assert!(alice_store.load_session(&bob_address).await?.is_some());
            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            assert!(bob_store.get_pre_key(pre_key_id).await.is_ok());
            let outgoing_message = encrypt(alice_store, &bob_address, original_message).await?;

            assert_eq!(
                outgoing_message.message_type(),
                CiphertextMessageType::PreKey
            );

            let outgoing_message = outgoing_message.serialize().to_vec();

            let mut corrupted_message: Vec<u8> = outgoing_message.clone();
            corrupted_message[outgoing_message.len() - 10] ^= 1;

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(corrupted_message.as_slice())?,
            );

            assert!(
                decrypt(bob_store, &alice_address, &incoming_message,)
                    .await
                    .is_err()
            );
            assert!(bob_store.get_pre_key(pre_key_id).await.is_ok());

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message.as_slice())?,
            );

            let ptext = decrypt(bob_store, &alice_address, &incoming_message).await?;

            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );
            assert!(matches!(
                bob_store.get_pre_key(pre_key_id).await.unwrap_err(),
                SignalProtocolError::InvalidPreKeyId
            ));

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_optional_one_time_prekey() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new();
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_signed_pre_key(22.into())
        .with_kyber_pre_key(8000.into());
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
        expected_session_version: u32,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();
            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            let outgoing_message = encrypt(alice_store, &bob_address, original_message).await?;

            assert_eq!(
                outgoing_message.message_type(),
                CiphertextMessageType::PreKey
            );

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message.serialize())?,
            );

            let ptext = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &incoming_message,
            )
            .await?;

            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_basic_session() -> TestResult {
    let (alice_session, bob_session) = initialize_sessions_v4()?;
    run_session_interaction(alice_session, bob_session)?;
    Ok(())
}

#[test]
fn test_message_key_limits() -> TestResult {
    run(initialize_sessions_v4()?)?;

    fn run(sessions: (SessionRecord, SessionRecord)) -> TestResult {
        async {
            let (alice_session_record, bob_session_record) = sessions;

            let alice_address =
                ProtocolAddress::new("+14159999999".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14158888888".to_owned(), DeviceId::new(1).unwrap());

            let mut alice_store = TestStoreBuilder::new().store;
            let mut bob_store = TestStoreBuilder::new().store;

            alice_store
                .store_session(&bob_address, &alice_session_record)
                .await?;
            bob_store
                .store_session(&alice_address, &bob_session_record)
                .await?;

            const MAX_MESSAGE_KEYS: usize = 2000; // same value as in library
            const TOO_MANY_MESSAGES: usize = MAX_MESSAGE_KEYS + 300;

            let mut inflight = Vec::with_capacity(TOO_MANY_MESSAGES);

            for i in 0..TOO_MANY_MESSAGES {
                inflight.push(
                    encrypt(&mut alice_store, &bob_address, &format!("It's over {i}")).await?,
                );
            }

            assert_eq!(
                String::from_utf8(decrypt(&mut bob_store, &alice_address, &inflight[1000],).await?)
                    .expect("valid utf8"),
                "It's over 1000"
            );
            assert_eq!(
                String::from_utf8(
                    decrypt(
                        &mut bob_store,
                        &alice_address,
                        &inflight[TOO_MANY_MESSAGES - 1],
                    )
                    .await?
                )
                .expect("valid utf8"),
                format!("It's over {}", TOO_MANY_MESSAGES - 1)
            );

            let err = decrypt(&mut bob_store, &alice_address, &inflight[5])
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                SignalProtocolError::DuplicatedMessage(2300, 5)
            ));
            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_basic_simultaneous_initiate() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
        expected_session_version: u32,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let alice_pre_key_bundle =
                alice_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());
            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            let message_for_bob = encrypt(alice_store, &bob_address, "hi bob").await?;
            let message_for_alice = encrypt(bob_store, &alice_address, "hi alice").await?;

            assert_eq!(
                message_for_bob.message_type(),
                CiphertextMessageType::PreKey
            );
            assert_eq!(
                message_for_alice.message_type(),
                CiphertextMessageType::PreKey
            );

            assert!(
                !is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let alice_plaintext = decrypt(
                alice_store,
                &bob_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_alice.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(alice_plaintext).expect("valid utf8"),
                "hi alice"
            );

            let bob_plaintext = decrypt(
                bob_store,
                &alice_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(bob_plaintext).expect("valid utf8"),
                "hi bob"
            );

            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );
            assert_eq!(
                bob_store.session_version(&alice_address)?,
                expected_session_version
            );

            assert!(
                !is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let alice_response = encrypt(alice_store, &bob_address, "nice to see you").await?;

            assert_eq!(
                alice_response.message_type(),
                CiphertextMessageType::Whisper
            );

            let response_plaintext = decrypt(
                bob_store,
                &alice_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    alice_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "nice to see you"
            );

            assert!(
                is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let bob_response = encrypt(bob_store, &alice_address, "you as well").await?;

            assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

            let response_plaintext = decrypt(
                alice_store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    bob_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "you as well"
            );

            assert!(
                is_session_id_equal(bob_store, &bob_address, alice_store, &alice_address).await?
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_simultaneous_initiate_with_lossage() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
        expected_session_version: u32,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let alice_pre_key_bundle =
                alice_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());
            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            let message_for_bob = encrypt(alice_store, &bob_address, "hi bob").await?;
            let message_for_alice = encrypt(bob_store, &alice_address, "hi alice").await?;

            assert_eq!(
                message_for_bob.message_type(),
                CiphertextMessageType::PreKey
            );
            assert_eq!(
                message_for_alice.message_type(),
                CiphertextMessageType::PreKey
            );

            assert!(
                !is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let bob_plaintext = decrypt(
                bob_store,
                &alice_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(bob_plaintext).expect("valid utf8"),
                "hi bob"
            );

            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );
            assert_eq!(
                bob_store.session_version(&alice_address)?,
                expected_session_version
            );

            let alice_response = encrypt(alice_store, &bob_address, "nice to see you").await?;

            assert_eq!(alice_response.message_type(), CiphertextMessageType::PreKey);

            let response_plaintext = decrypt(
                bob_store,
                &alice_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    alice_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "nice to see you"
            );

            assert!(
                is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let bob_response = encrypt(bob_store, &alice_address, "you as well").await?;

            assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

            let response_plaintext = decrypt(
                alice_store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    bob_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "you as well"
            );

            assert!(
                is_session_id_equal(bob_store, &bob_address, alice_store, &alice_address).await?
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_simultaneous_initiate_lost_message() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
        expected_session_version: u32,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let alice_pre_key_bundle =
                alice_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());
            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            let message_for_bob = encrypt(alice_store, &bob_address, "hi bob").await?;
            let message_for_alice = encrypt(bob_store, &alice_address, "hi alice").await?;

            assert_eq!(
                message_for_bob.message_type(),
                CiphertextMessageType::PreKey
            );
            assert_eq!(
                message_for_alice.message_type(),
                CiphertextMessageType::PreKey
            );

            assert!(
                !is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let alice_plaintext = decrypt(
                alice_store,
                &bob_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_alice.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(alice_plaintext).expect("valid utf8"),
                "hi alice"
            );

            let bob_plaintext = decrypt(
                bob_store,
                &alice_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(bob_plaintext).expect("valid utf8"),
                "hi bob"
            );

            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );
            assert_eq!(
                bob_store.session_version(&alice_address)?,
                expected_session_version
            );

            assert!(
                !is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let alice_response = encrypt(alice_store, &bob_address, "nice to see you").await?;

            assert_eq!(
                alice_response.message_type(),
                CiphertextMessageType::Whisper
            );

            assert!(
                !is_session_id_equal(alice_store, &alice_address, bob_store, &bob_address).await?
            );

            let bob_response = encrypt(bob_store, &alice_address, "you as well").await?;

            assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

            let response_plaintext = decrypt(
                alice_store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    bob_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "you as well"
            );

            assert!(
                is_session_id_equal(bob_store, &bob_address, alice_store, &alice_address).await?
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_simultaneous_initiate_repeated_messages() -> TestResult {
    let mut alice_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random)
        .with_kyber_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run(
        alice_store_builder: &mut TestStoreBuilder,
        bob_store_builder: &mut TestStoreBuilder,
        expected_session_version: u32,
    ) -> TestResult {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            for _ in 0..15 {
                let alice_pre_key_bundle =
                    alice_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());
                let bob_pre_key_bundle =
                    bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store_builder.store.session_store,
                    &mut alice_store_builder.store.identity_store,
                    &bob_pre_key_bundle,
                    SystemTime::now(),
                    &mut csprng,
                )
                .await?;

                process_prekey_bundle(
                    &alice_address,
                    &mut bob_store_builder.store.session_store,
                    &mut bob_store_builder.store.identity_store,
                    &alice_pre_key_bundle,
                    SystemTime::now(),
                    &mut csprng,
                )
                .await?;

                let message_for_bob =
                    encrypt(&mut alice_store_builder.store, &bob_address, "hi bob").await?;
                let message_for_alice =
                    encrypt(&mut bob_store_builder.store, &alice_address, "hi alice").await?;

                assert_eq!(
                    message_for_bob.message_type(),
                    CiphertextMessageType::PreKey
                );
                assert_eq!(
                    message_for_alice.message_type(),
                    CiphertextMessageType::PreKey
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );

                let alice_plaintext = decrypt(
                    &mut alice_store_builder.store,
                    &bob_address,
                    &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                        message_for_alice.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(alice_plaintext).expect("valid utf8"),
                    "hi alice"
                );

                let bob_plaintext = decrypt(
                    &mut bob_store_builder.store,
                    &alice_address,
                    &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                        message_for_bob.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(bob_plaintext).expect("valid utf8"),
                    "hi bob"
                );

                assert_eq!(
                    alice_store_builder.session_version(&bob_address)?,
                    expected_session_version
                );
                assert_eq!(
                    bob_store_builder.session_version(&alice_address)?,
                    expected_session_version
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );
            }

            for _ in 0..50 {
                let message_for_bob =
                    encrypt(&mut alice_store_builder.store, &bob_address, "hi bob").await?;
                let message_for_alice =
                    encrypt(&mut bob_store_builder.store, &alice_address, "hi alice").await?;

                assert_eq!(
                    message_for_bob.message_type(),
                    CiphertextMessageType::Whisper
                );
                assert_eq!(
                    message_for_alice.message_type(),
                    CiphertextMessageType::Whisper
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );

                let alice_plaintext = decrypt(
                    &mut alice_store_builder.store,
                    &bob_address,
                    &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                        message_for_alice.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(alice_plaintext).expect("valid utf8"),
                    "hi alice"
                );

                let bob_plaintext = decrypt(
                    &mut bob_store_builder.store,
                    &alice_address,
                    &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                        message_for_bob.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(bob_plaintext).expect("valid utf8"),
                    "hi bob"
                );

                assert_eq!(
                    alice_store_builder.session_version(&bob_address)?,
                    expected_session_version
                );
                assert_eq!(
                    bob_store_builder.session_version(&alice_address)?,
                    expected_session_version
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );
            }

            let alice_response = encrypt(
                &mut alice_store_builder.store,
                &bob_address,
                "nice to see you",
            )
            .await?;

            assert_eq!(
                alice_response.message_type(),
                CiphertextMessageType::Whisper
            );

            assert!(
                !is_session_id_equal(
                    &alice_store_builder.store,
                    &alice_address,
                    &bob_store_builder.store,
                    &bob_address,
                )
                .await?
            );

            let bob_response =
                encrypt(&mut bob_store_builder.store, &alice_address, "you as well").await?;

            assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

            let response_plaintext = decrypt(
                &mut alice_store_builder.store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    bob_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "you as well"
            );

            assert!(
                is_session_id_equal(
                    &bob_store_builder.store,
                    &bob_address,
                    &alice_store_builder.store,
                    &alice_address,
                )
                .await?
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_simultaneous_initiate_lost_message_repeated_messages() -> TestResult {
    run(
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
            builder.add_kyber_pre_key(IdChoice::Next);
        },
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run<F>(add_keys: F, expected_session_version: u32) -> TestResult
    where
        F: Fn(&mut TestStoreBuilder),
    {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address =
                ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

            let mut alice_store_builder = TestStoreBuilder::new();
            add_keys(&mut alice_store_builder);
            let mut bob_store_builder = TestStoreBuilder::new();
            add_keys(&mut bob_store_builder);

            let bob_pre_key_bundle =
                bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store_builder.store.session_store,
                &mut alice_store_builder.store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;
            let lost_message_for_bob = encrypt(
                &mut alice_store_builder.store,
                &bob_address,
                "it was so long ago",
            )
            .await?;

            for i in 0..15 {
                add_keys(&mut alice_store_builder);
                add_keys(&mut bob_store_builder);

                let alice_pre_key_bundle =
                    alice_store_builder.make_bundle_with_latest_keys(DeviceId::new(i + 2).unwrap());
                let bob_pre_key_bundle =
                    bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(i + 2).unwrap());

                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store_builder.store.session_store,
                    &mut alice_store_builder.store.identity_store,
                    &bob_pre_key_bundle,
                    SystemTime::now(),
                    &mut csprng,
                )
                .await?;

                process_prekey_bundle(
                    &alice_address,
                    &mut bob_store_builder.store.session_store,
                    &mut bob_store_builder.store.identity_store,
                    &alice_pre_key_bundle,
                    SystemTime::now(),
                    &mut csprng,
                )
                .await?;

                let message_for_bob =
                    encrypt(&mut alice_store_builder.store, &bob_address, "hi bob").await?;
                let message_for_alice =
                    encrypt(&mut bob_store_builder.store, &alice_address, "hi alice").await?;

                assert_eq!(
                    message_for_bob.message_type(),
                    CiphertextMessageType::PreKey
                );
                assert_eq!(
                    message_for_alice.message_type(),
                    CiphertextMessageType::PreKey
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );

                let alice_plaintext = decrypt(
                    &mut alice_store_builder.store,
                    &bob_address,
                    &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                        message_for_alice.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(alice_plaintext).expect("valid utf8"),
                    "hi alice"
                );

                let bob_plaintext = decrypt(
                    &mut bob_store_builder.store,
                    &alice_address,
                    &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                        message_for_bob.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(bob_plaintext).expect("valid utf8"),
                    "hi bob"
                );

                assert_eq!(
                    alice_store_builder.session_version(&bob_address)?,
                    expected_session_version
                );
                assert_eq!(
                    bob_store_builder.session_version(&alice_address)?,
                    expected_session_version
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );
            }

            for _ in 0..50 {
                let message_for_bob =
                    encrypt(&mut alice_store_builder.store, &bob_address, "hi bob").await?;
                let message_for_alice =
                    encrypt(&mut bob_store_builder.store, &alice_address, "hi alice").await?;

                assert_eq!(
                    message_for_bob.message_type(),
                    CiphertextMessageType::Whisper
                );
                assert_eq!(
                    message_for_alice.message_type(),
                    CiphertextMessageType::Whisper
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );

                let alice_plaintext = decrypt(
                    &mut alice_store_builder.store,
                    &bob_address,
                    &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                        message_for_alice.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(alice_plaintext).expect("valid utf8"),
                    "hi alice"
                );

                let bob_plaintext = decrypt(
                    &mut bob_store_builder.store,
                    &alice_address,
                    &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                        message_for_bob.serialize(),
                    )?),
                )
                .await?;
                assert_eq!(
                    String::from_utf8(bob_plaintext).expect("valid utf8"),
                    "hi bob"
                );

                assert_eq!(
                    alice_store_builder.session_version(&bob_address)?,
                    expected_session_version
                );
                assert_eq!(
                    bob_store_builder.session_version(&alice_address)?,
                    expected_session_version
                );

                assert!(
                    !is_session_id_equal(
                        &alice_store_builder.store,
                        &alice_address,
                        &bob_store_builder.store,
                        &bob_address,
                    )
                    .await?
                );
            }

            let alice_response = encrypt(
                &mut alice_store_builder.store,
                &bob_address,
                "nice to see you",
            )
            .await?;

            assert_eq!(
                alice_response.message_type(),
                CiphertextMessageType::Whisper
            );

            assert!(
                !is_session_id_equal(
                    &alice_store_builder.store,
                    &alice_address,
                    &bob_store_builder.store,
                    &bob_address,
                )
                .await?
            );

            let bob_response =
                encrypt(&mut bob_store_builder.store, &alice_address, "you as well").await?;

            assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

            let response_plaintext = decrypt(
                &mut alice_store_builder.store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    bob_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "you as well"
            );

            assert!(
                is_session_id_equal(
                    &bob_store_builder.store,
                    &bob_address,
                    &alice_store_builder.store,
                    &alice_address,
                )
                .await?
            );

            let blast_from_the_past = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                    lost_message_for_bob.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(blast_from_the_past).expect("valid utf8"),
                "it was so long ago"
            );

            assert!(
                !is_session_id_equal(
                    &bob_store_builder.store,
                    &bob_address,
                    &alice_store_builder.store,
                    &alice_address,
                )
                .await?
            );

            let bob_response =
                encrypt(&mut bob_store_builder.store, &alice_address, "so it was").await?;

            assert_eq!(bob_response.message_type(), CiphertextMessageType::Whisper);

            let response_plaintext = decrypt(
                &mut alice_store_builder.store,
                &bob_address,
                &CiphertextMessage::SignalMessage(SignalMessage::try_from(
                    bob_response.serialize(),
                )?),
            )
            .await?;
            assert_eq!(
                String::from_utf8(response_plaintext).expect("valid utf8"),
                "so it was"
            );

            assert!(
                is_session_id_equal(
                    &bob_store_builder.store,
                    &bob_address,
                    &alice_store_builder.store,
                    &alice_address,
                )
                .await?
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }

    Ok(())
}

#[test]
fn test_zero_is_a_valid_prekey_id() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();
        let alice_address =
            ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
        let bob_address =
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store_builder = TestStoreBuilder::new()
            .with_pre_key(0.into())
            .with_signed_pre_key(0.into())
            .with_kyber_pre_key(0.into());

        let bob_pre_key_bundle =
            bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        assert_eq!(
            alice_store
                .load_session(&bob_address)
                .await?
                .expect("session found")
                .session_version()?,
            KYBER_AWARE_MESSAGE_VERSION
        );

        let original_message = "L'homme est condamné à être libre";

        let outgoing_message = encrypt(&mut alice_store, &bob_address, original_message).await?;

        assert_eq!(
            outgoing_message.message_type(),
            CiphertextMessageType::PreKey
        );

        let incoming_message = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(outgoing_message.serialize())?,
        );

        let ptext = decrypt(
            &mut bob_store_builder.store,
            &alice_address,
            &incoming_message,
        )
        .await?;

        assert_eq!(
            String::from_utf8(ptext).expect("valid utf8"),
            original_message
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_unacknowledged_sessions_eventually_expire() -> TestResult {
    async {
        const WELL_PAST_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 90);

        let mut csprng = OsRng.unwrap_err();
        let bob_address =
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

        let mut alice_store = TestStoreBuilder::new().store;
        let bob_store_builder = TestStoreBuilder::new()
            .with_pre_key(0.into())
            .with_signed_pre_key(0.into())
            .with_kyber_pre_key(0.into());

        let bob_pre_key_bundle =
            bob_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .await?;

        let initial_session = alice_store
            .session_store
            .load_session(&bob_address)
            .await
            .expect("session can be loaded")
            .expect("session exists");
        assert!(
            initial_session
                .has_usable_sender_chain(
                    SystemTime::UNIX_EPOCH,
                    SessionUsabilityRequirements::NotStale
                )
                .expect("can check for a sender chain")
        );
        assert!(
            !initial_session
                .has_usable_sender_chain(
                    SystemTime::UNIX_EPOCH + WELL_PAST_EXPIRATION,
                    SessionUsabilityRequirements::NotStale
                )
                .expect("can check for a sender chain")
        );
        assert!(
            initial_session
                .has_usable_sender_chain(
                    SystemTime::UNIX_EPOCH + WELL_PAST_EXPIRATION,
                    SessionUsabilityRequirements::empty()
                )
                .expect("respects usability requirements")
        );

        let original_message = "L'homme est condamné à être libre";
        let outgoing_message = message_encrypt(
            original_message.as_bytes(),
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            &mut csprng,
        )
        .await?;

        assert_eq!(
            outgoing_message.message_type(),
            CiphertextMessageType::PreKey
        );

        let updated_session = alice_store
            .session_store
            .load_session(&bob_address)
            .await
            .expect("session can be loaded")
            .expect("session exists");
        assert!(
            updated_session
                .has_usable_sender_chain(
                    SystemTime::UNIX_EPOCH,
                    SessionUsabilityRequirements::NotStale
                )
                .expect("can check for a sender chain")
        );
        assert!(
            !updated_session
                .has_usable_sender_chain(
                    SystemTime::UNIX_EPOCH + WELL_PAST_EXPIRATION,
                    SessionUsabilityRequirements::NotStale
                )
                .expect("can check for a sender chain")
        );

        let error = message_encrypt(
            original_message.as_bytes(),
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::UNIX_EPOCH + WELL_PAST_EXPIRATION,
            &mut csprng,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, SignalProtocolError::SessionNotFound(addr) if addr == &bob_address),
            "{error:?}"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn prekey_message_failed_decryption_does_not_update_stores() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();
        let alice_address =
            ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
        let bob_address =
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

        let alice_store_builder = TestStoreBuilder::new()
            .with_pre_key(0.into())
            .with_signed_pre_key(0.into())
            .with_kyber_pre_key(0.into());
        let alice_pre_key_bundle =
            alice_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

        let mut alice_store = alice_store_builder.store;

        let mut bob_store = TestStoreBuilder::new().store;
        process_prekey_bundle(
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            SystemTime::UNIX_EPOCH,
            &mut csprng,
        )
        .await
        .expect("can receive bundle");

        // Bob sends a pre-key message that doesn't decrypt successfully.
        let pre_key_message = {
            let message = message_encrypt(
                "from Bob".as_bytes(),
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                SystemTime::UNIX_EPOCH,
                &mut csprng,
            )
            .await;
            let message =
                assert_matches!(message, Ok(CiphertextMessage::PreKeySignalMessage(m)) => m);

            // Perturb the ciphertext so it doesn't decrypt successfully, but
            // don't touch anything else.
            let mut signal_message = message.message().serialized().to_owned();
            let last_byte = signal_message.last_mut().unwrap();
            *last_byte = last_byte.wrapping_add(1);

            PreKeySignalMessage::new(
                message.message_version(),
                message.registration_id(),
                message.pre_key_id(),
                message.signed_pre_key_id(),
                message
                    .kyber_pre_key_id()
                    .zip(message.kyber_ciphertext())
                    .map(|(id, ciphertext)| KyberPayload::new(id, ciphertext.clone())),
                *message.base_key(),
                *message.identity_key(),
                (&*signal_message).try_into().unwrap(),
            )
            .unwrap()
        };

        // The decryption fails, as expected.
        assert_matches!(
            decrypt(
                &mut alice_store,
                &bob_address,
                &CiphertextMessage::PreKeySignalMessage(pre_key_message),
            )
            .await,
            Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "decryption failed"
            ))
        );

        // Because the decryption failed, the identity and session stores were
        // not updated.
        assert_eq!(
            alice_store
                .identity_store
                .get_identity(&bob_address)
                .await
                .unwrap(),
            None
        );

        assert!(
            alice_store
                .session_store
                .load_session(&bob_address)
                .await
                .expect("can load")
                .is_none()
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn prekey_message_failed_decryption_does_not_update_stores_even_when_previously_archived()
-> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();
        let alice_address =
            ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
        let bob_address =
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

        let alice_store_builder = TestStoreBuilder::new()
            .with_pre_key(0.into())
            .with_signed_pre_key(0.into())
            .with_kyber_pre_key(0.into());
        let alice_pre_key_bundle =
            alice_store_builder.make_bundle_with_latest_keys(DeviceId::new(1).unwrap());

        let mut alice_store = alice_store_builder.store;

        let mut bob_store = TestStoreBuilder::new().store;
        process_prekey_bundle(
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("can receive bundle");

        // Bob sends a message that decrypts just fine.
        let bob_ciphertext = encrypt(&mut bob_store, &alice_address, "from Bob")
            .await
            .expect("valid");
        _ = decrypt(&mut alice_store, &bob_address, &bob_ciphertext)
            .await
            .expect("valid");

        // Alice archives the session because she feels like it.
        let mut alice_session_with_bob = alice_store
            .load_session(&bob_address)
            .await
            .expect("can load")
            .expect("has session record");
        assert!(
            alice_session_with_bob
                .has_usable_sender_chain(SystemTime::now(), SessionUsabilityRequirements::all())
                .expect("can ask about sender chains")
        );
        alice_session_with_bob
            .archive_current_state()
            .expect("can archive");
        assert!(
            !alice_session_with_bob
                .has_usable_sender_chain(SystemTime::now(), SessionUsabilityRequirements::empty())
                .expect("can ask about sender chains")
        );
        alice_store
            .store_session(&bob_address, &alice_session_with_bob)
            .await
            .expect("can save");

        // Bob sends a pre-key message that doesn't decrypt successfully.
        let pre_key_message = {
            let message = message_encrypt(
                "from Bob".as_bytes(),
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                SystemTime::now(),
                &mut csprng,
            )
            .await;
            let message =
                assert_matches!(message, Ok(CiphertextMessage::PreKeySignalMessage(m)) => m);

            // Perturb the ciphertext so it doesn't decrypt successfully, but
            // don't touch anything else.
            let mut signal_message = message.message().serialized().to_owned();
            let last_byte = signal_message.last_mut().unwrap();
            *last_byte = last_byte.wrapping_add(1);

            PreKeySignalMessage::new(
                message.message_version(),
                message.registration_id(),
                message.pre_key_id(),
                message.signed_pre_key_id(),
                message
                    .kyber_pre_key_id()
                    .zip(message.kyber_ciphertext())
                    .map(|(id, ciphertext)| KyberPayload::new(id, ciphertext.clone())),
                *message.base_key(),
                *message.identity_key(),
                (&*signal_message).try_into().unwrap(),
            )
            .unwrap()
        };

        // The decryption fails, as expected.
        assert_matches!(
            decrypt(
                &mut alice_store,
                &bob_address,
                &CiphertextMessage::PreKeySignalMessage(pre_key_message),
            )
            .await,
            Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "decryption failed"
            ))
        );

        // Because the decryption failed, the session should still be archived.
        let alice_current_session_with_bob = alice_store
            .session_store
            .load_session(&bob_address)
            .await
            .expect("can load")
            .expect("has session record");

        assert!(
            !alice_current_session_with_bob
                .has_usable_sender_chain(SystemTime::now(), SessionUsabilityRequirements::empty())
                .expect("can ask about sender chains")
        );
        assert_eq!(
            &alice_session_with_bob.serialize().expect("can serialize"),
            &alice_current_session_with_bob
                .serialize()
                .expect("can serialize")
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn prekey_message_to_archived_session() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();
        let alice_address =
            ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
        let bob_address =
            ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());

        let alice_store_builder = TestStoreBuilder::new()
            .with_pre_key(0.into())
            .with_signed_pre_key(0.into())
            .with_kyber_pre_key(0.into());
        let alice_pre_key_bundle =
            alice_store_builder.make_bundle_with_latest_keys(alice_address.device_id());
        let mut alice_store = alice_store_builder.store;

        let bob_store_builder = TestStoreBuilder::new()
            .with_pre_key(10.into())
            .with_signed_pre_key(10.into())
            .with_kyber_pre_key(10.into());
        let bob_pre_key_bundle =
            bob_store_builder.make_bundle_with_latest_keys(bob_address.device_id());
        let mut bob_store = bob_store_builder.store;

        // First Bob sends a message to Alice.
        process_prekey_bundle(
            &alice_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("can receive bundle");

        let bob_ciphertext = encrypt(&mut bob_store, &alice_address, "from Bob")
            .await
            .expect("valid");
        assert_eq!(bob_ciphertext.message_type(), CiphertextMessageType::PreKey);

        // Alice receives the message.
        let received_message = decrypt(&mut alice_store, &bob_address, &bob_ciphertext)
            .await
            .expect("valid");
        assert_eq!(received_message, b"from Bob");

        // Alice decides to archive the session and then send a message to Bob on a new session.
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("can receive bundle");

        // (This is technically unnecessary, the process_prekey_bundle is sufficient, but it's illustrative.)
        let unsent_alice_ciphertext = encrypt(&mut alice_store, &bob_address, "from Alice")
            .await
            .expect("valid");
        assert_eq!(
            unsent_alice_ciphertext.message_type(),
            CiphertextMessageType::PreKey
        );

        // But before Alice can send the message, she gets a second message from Bob.
        let bob_ciphertext_2 = encrypt(&mut bob_store, &alice_address, "from Bob 2")
            .await
            .expect("valid");
        assert_eq!(
            bob_ciphertext_2.message_type(),
            CiphertextMessageType::PreKey
        );
        let received_message_2 = decrypt(&mut alice_store, &bob_address, &bob_ciphertext_2)
            .await
            .expect("valid");
        assert_eq!(received_message_2, b"from Bob 2");

        // This should promote Bob's session back to the front of Alice's session state.
        let alice_session_record = alice_store
            .load_session(&bob_address)
            .await
            .expect("no errors")
            .expect("Alice has a session with Bob");
        let bob_session_record = bob_store
            .load_session(&alice_address)
            .await
            .expect("no errors")
            .expect("Bob has a session with Alice");
        assert_eq!(
            alice_session_record
                .alice_base_key()
                .expect("has current session with valid base key"),
            bob_session_record
                .alice_base_key()
                .expect("has current session with valid base key")
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[expect(clippy::needless_range_loop)]
fn run_session_interaction(alice_session: SessionRecord, bob_session: SessionRecord) -> TestResult {
    async {
        use rand::seq::SliceRandom;

        let alice_address =
            ProtocolAddress::new("+14159999999".to_owned(), DeviceId::new(1).unwrap());
        let bob_address =
            ProtocolAddress::new("+14158888888".to_owned(), DeviceId::new(1).unwrap());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;

        alice_store
            .store_session(&bob_address, &alice_session)
            .await?;
        bob_store
            .store_session(&alice_address, &bob_session)
            .await?;

        let alice_plaintext = "This is Alice's message";
        let alice_ciphertext = encrypt(&mut alice_store, &bob_address, alice_plaintext).await?;
        let bob_decrypted = decrypt(&mut bob_store, &alice_address, &alice_ciphertext).await?;
        assert_eq!(
            String::from_utf8(bob_decrypted).expect("valid utf8"),
            alice_plaintext
        );

        let bob_plaintext = "This is Bob's reply";

        let bob_ciphertext = encrypt(&mut bob_store, &alice_address, bob_plaintext).await?;
        let alice_decrypted = decrypt(&mut alice_store, &bob_address, &bob_ciphertext).await?;
        assert_eq!(
            String::from_utf8(alice_decrypted).expect("valid utf8"),
            bob_plaintext
        );

        const ALICE_MESSAGE_COUNT: usize = 50;
        const BOB_MESSAGE_COUNT: usize = 50;

        let mut alice_messages = Vec::with_capacity(ALICE_MESSAGE_COUNT);

        for i in 0..ALICE_MESSAGE_COUNT {
            let ptext = format!("смерть за смерть {i}");
            let ctext = encrypt(&mut alice_store, &bob_address, &ptext).await?;
            alice_messages.push((ptext, ctext));
        }

        let mut rng = rand::rngs::OsRng.unwrap_err();

        alice_messages.shuffle(&mut rng);

        for i in 0..ALICE_MESSAGE_COUNT / 2 {
            let ptext = decrypt(&mut bob_store, &alice_address, &alice_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                alice_messages[i].0
            );
        }

        let mut bob_messages = Vec::with_capacity(BOB_MESSAGE_COUNT);

        for i in 0..BOB_MESSAGE_COUNT {
            let ptext = format!("Relax in the safety of your own delusions. {i}");
            let ctext = encrypt(&mut bob_store, &alice_address, &ptext).await?;
            bob_messages.push((ptext, ctext));
        }

        bob_messages.shuffle(&mut rng);

        for i in 0..BOB_MESSAGE_COUNT / 2 {
            let ptext = decrypt(&mut alice_store, &bob_address, &bob_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                bob_messages[i].0
            );
        }

        for i in ALICE_MESSAGE_COUNT / 2..ALICE_MESSAGE_COUNT {
            let ptext = decrypt(&mut bob_store, &alice_address, &alice_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                alice_messages[i].0
            );
        }

        for i in BOB_MESSAGE_COUNT / 2..BOB_MESSAGE_COUNT {
            let ptext = decrypt(&mut alice_store, &bob_address, &bob_messages[i].1).await?;
            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                bob_messages[i].0
            );
        }

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

async fn run_interaction(
    alice_store: &mut InMemSignalProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &mut InMemSignalProtocolStore,
    bob_address: &ProtocolAddress,
) -> TestResult {
    let alice_ptext = "It's rabbit season";

    let alice_message = encrypt(alice_store, bob_address, alice_ptext).await?;
    assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
            .expect("valid utf8"),
        alice_ptext
    );

    let bob_ptext = "It's duck season";

    let bob_message = encrypt(bob_store, alice_address, bob_ptext).await?;
    assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
    assert_eq!(
        String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
            .expect("valid utf8"),
        bob_ptext
    );

    for i in 0..10 {
        let alice_ptext = format!("A->B message {i}");
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message {i}");
        let bob_message = encrypt(bob_store, alice_address, &bob_ptext).await?;
        assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
                .expect("valid utf8"),
            bob_ptext
        );
    }

    let mut alice_ooo_messages = vec![];

    for i in 0..10 {
        let alice_ptext = format!("A->B OOO message {i}");
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        alice_ooo_messages.push((alice_ptext, alice_message));
    }

    for i in 0..10 {
        let alice_ptext = format!("A->B post-OOO message {i}");
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message post-OOO {i}");
        let bob_message = encrypt(bob_store, alice_address, &bob_ptext).await?;
        assert_eq!(bob_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(alice_store, bob_address, &bob_message).await?)
                .expect("valid utf8"),
            bob_ptext
        );
    }

    for (ptext, ctext) in alice_ooo_messages {
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &ctext).await?)
                .expect("valid utf8"),
            ptext
        );
    }

    Ok(())
}

#[test]
fn test_signedprekey_not_saved() -> TestResult {
    run(
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
            builder.add_kyber_pre_key(IdChoice::Next);
        },
        KYBER_AWARE_MESSAGE_VERSION,
    )?;

    fn run<F>(bob_add_keys: F, expected_session_version: u32) -> TestResult
    where
        F: Fn(&mut TestStoreBuilder),
    {
        async {
            let mut csprng = OsRng.unwrap_err();

            let bob_device_id = DeviceId::new(1).unwrap();

            let alice_address =
                ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

            let mut bob_store_builder = TestStoreBuilder::new();
            bob_add_keys(&mut bob_store_builder);

            let mut alice_store_builder = TestStoreBuilder::new();
            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            assert!(alice_store.load_session(&bob_address).await?.is_some());
            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            // We encrypt a first message
            let outgoing_message = encrypt(alice_store, &bob_address, original_message).await?;

            // We encrypt a second message
            let original_message2 = "L'homme est condamné à nouveau à être libre";
            let outgoing_message2 = encrypt(alice_store, &bob_address, original_message2).await?;

            assert_eq!(
                outgoing_message.message_type(),
                CiphertextMessageType::PreKey
            );

            // Let's process message 1
            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message.serialize())?,
            );

            let ptext = decrypt(
                &mut bob_store_builder.store,
                &alice_address,
                &incoming_message,
            )
            .await?;

            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );

            // Now, we do not process the actual outgoing_message2, we clone it
            let pksm_og2 = PreKeySignalMessage::try_from(outgoing_message2.serialize())?;
            let kyber_payload = if let (Some(id), Some(ct)) =
                (pksm_og2.kyber_pre_key_id(), pksm_og2.kyber_ciphertext())
            {
                // Note that we're relying on the Kyber pre-key being treated like a "last-resort"
                // key and not being deleted between the two messages.
                Some(KyberPayload::new(id, ct.clone()))
            } else {
                None
            };

            let arbitrary_other_base_key = KeyPair::generate(&mut csprng);

            // and then recreate from outgoing_message2 a new fresh prekey message
            let pksm_mal = PreKeySignalMessage::new(
                pksm_og2.message_version(),
                pksm_og2.registration_id(),
                None, // we don't bother with a one time prekey
                pksm_og2.signed_pre_key_id(),
                kyber_payload,
                arbitrary_other_base_key.public_key,
                *pksm_og2.identity_key(),
                pksm_og2.message().clone(), // but we keep the originally computed ciphertext
            )
            .expect("ok");

            // Now process pksm_mal
            let bob_session_state_before = bob_store_builder
                .store
                .load_session(&alice_address)
                .await?
                .expect("session found")
                .serialize()?;
            let incoming_message = CiphertextMessage::PreKeySignalMessage(pksm_mal);
            assert_matches!(
                decrypt(
                    &mut bob_store_builder.store,
                    &alice_address,
                    &incoming_message,
                )
                .await
                .expect_err("invalid"),
                SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, _)
            );
            let bob_session_state_after = bob_store_builder
                .store
                .load_session(&alice_address)
                .await?
                .expect("session found")
                .serialize()?;
            assert_eq!(
                bob_session_state_before, bob_session_state_after,
                "session should not have been updated on decryption failure"
            );

            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }
    Ok(())
}

async fn is_session_id_equal(
    alice_store: &dyn ProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &dyn ProtocolStore,
    bob_address: &ProtocolAddress,
) -> Result<bool, SignalProtocolError> {
    Ok(alice_store
        .load_session(bob_address)
        .await?
        .expect("session found")
        .alice_base_key()?
        == bob_store
            .load_session(alice_address)
            .await?
            .expect("session found")
            .alice_base_key()?)
}

enum LongerSessionActions {
    AliceSend,
    BobSend,
    AliceRecv,
    BobRecv,
    AliceDrop,
    BobDrop,
    AliceReorder,
    BobReorder,
}

#[test]
fn test_longer_sessions() -> TestResult {
    init_logger();
    run(
        2000,
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
            builder.add_kyber_pre_key(IdChoice::Next);
        },
        // All equally likely
        &[
            LongerSessionActions::AliceSend,
            LongerSessionActions::AliceRecv,
            LongerSessionActions::AliceDrop,
            LongerSessionActions::AliceReorder,
            LongerSessionActions::BobSend,
            LongerSessionActions::BobRecv,
            LongerSessionActions::BobDrop,
            LongerSessionActions::BobReorder,
        ],
    )?;

    run(
        2000,
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
            builder.add_kyber_pre_key(IdChoice::Next);
        },
        // All sends/drops more likely
        &[
            LongerSessionActions::AliceSend,
            LongerSessionActions::AliceSend,
            LongerSessionActions::AliceRecv,
            LongerSessionActions::AliceDrop,
            LongerSessionActions::AliceDrop,
            LongerSessionActions::AliceReorder,
            LongerSessionActions::BobSend,
            LongerSessionActions::BobSend,
            LongerSessionActions::BobRecv,
            LongerSessionActions::BobDrop,
            LongerSessionActions::BobDrop,
            LongerSessionActions::BobReorder,
        ],
    )?;

    run(
        2000,
        |builder| {
            builder.add_pre_key(IdChoice::Next);
            builder.add_signed_pre_key(IdChoice::Next);
            builder.add_kyber_pre_key(IdChoice::Next);
        },
        // All sends/reorders more likely
        &[
            LongerSessionActions::AliceSend,
            LongerSessionActions::AliceSend,
            LongerSessionActions::AliceRecv,
            LongerSessionActions::AliceDrop,
            LongerSessionActions::AliceReorder,
            LongerSessionActions::AliceReorder,
            LongerSessionActions::BobSend,
            LongerSessionActions::BobSend,
            LongerSessionActions::BobRecv,
            LongerSessionActions::BobDrop,
            LongerSessionActions::BobReorder,
            LongerSessionActions::BobReorder,
        ],
    )?;
    fn run<F>(steps: usize, add_keys: F, actions: &[LongerSessionActions]) -> TestResult
    where
        F: Fn(&mut TestStoreBuilder),
    {
        async {
            let mut csprng = OsRng.unwrap_err();

            let alice_device_id = DeviceId::new(1).unwrap();
            let bob_device_id = DeviceId::new(1).unwrap();

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), alice_device_id);
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

            let mut alice_store_builder = TestStoreBuilder::new();
            add_keys(&mut alice_store_builder);

            let mut bob_store_builder = TestStoreBuilder::new();
            add_keys(&mut bob_store_builder);

            let alice_pre_key_bundle =
                alice_store_builder.make_bundle_with_latest_keys(alice_device_id);
            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;
            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                SystemTime::now(),
                &mut csprng,
            )
            .await?;

            // Stores (reordered, msg) tuples, where `reordered` marks whether we've already reordered
            // this message (and thus it shouldn't be again).
            let mut to_alice = VecDeque::new();
            let mut to_bob = VecDeque::new();

            // We use a seeded RNG here so we can recreate failures should they occur in the future.
            let seed = csprng.next_u64();
            println!("starting random loop with seed {seed}");
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

            const MAX_OOO: usize = 30;

            for _i in 0..steps {
                match actions[rng.next_u32() as usize % actions.len()] {
                    LongerSessionActions::AliceSend => {
                        log::debug!("Send message to Alice");
                        to_alice.push_back((
                            false,
                            encrypt(bob_store, &alice_address, "wheee1").await?,
                        ));
                    }
                    LongerSessionActions::BobSend => {
                        log::debug!("Send message to Bob");
                        to_bob.push_back((
                            false,
                            encrypt(alice_store, &bob_address, "wheee2").await?,
                        ));
                    }
                    LongerSessionActions::AliceRecv => match to_alice.pop_front() {
                        None => {}
                        Some((_reordered, msg)) => {
                            log::debug!("Process message to Alice");
                            decrypt(alice_store, &bob_address, &msg).await?;
                        }
                    },
                    LongerSessionActions::BobRecv => match to_bob.pop_front() {
                        None => {}
                        Some((_reordered, msg)) => {
                            log::debug!("Process message to Bob");
                            decrypt(bob_store, &alice_address, &msg).await?;
                        }
                    },
                    LongerSessionActions::AliceDrop => {
                        log::debug!("Discard message to Alice");
                        to_alice.pop_front();
                    }
                    LongerSessionActions::BobDrop => {
                        log::debug!("Discard message to Bob");
                        to_bob.pop_front();
                    }
                    LongerSessionActions::AliceReorder => {
                        if to_alice.len() >= 2 {
                            let reorder_idx =
                                (rng.next_u32() as usize % MAX_OOO) % (to_alice.len() - 1) + 1;
                            // Don't reorder things that are already reordered, to maintain our MAX_OOO guarantee.
                            if !to_alice.front().unwrap().0 && !to_alice.get(reorder_idx).unwrap().0
                            {
                                log::debug!("Reorder message to Alice (0 <-> {reorder_idx})");
                                to_alice.swap(0, reorder_idx);
                                to_alice.get_mut(0).unwrap().0 = true;
                                to_alice.get_mut(reorder_idx).unwrap().0 = true;
                            }
                        }
                    }
                    LongerSessionActions::BobReorder => {
                        if to_bob.len() >= 2 {
                            let reorder_idx =
                                (rng.next_u32() as usize % MAX_OOO) % (to_bob.len() - 1) + 1;
                            // Don't reorder things that are already reordered, to maintain our MAX_OOO guarantee.
                            if !to_bob.front().unwrap().0 && !to_bob.get(reorder_idx).unwrap().0 {
                                log::debug!("Reorder message to Bob (0 <-> {reorder_idx})");
                                to_bob.swap(0, reorder_idx);
                                to_bob.get_mut(0).unwrap().0 = true;
                                to_bob.get_mut(reorder_idx).unwrap().0 = true;
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        .now_or_never()
        .expect("sync")
    }
    Ok(())
}

#[test]
fn test_duplicate_message_error_returned() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_device_id = DeviceId::new(1).unwrap();
        let bob_device_id = DeviceId::new(1).unwrap();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), alice_device_id);
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

        let mut alice_store_builder = TestStoreBuilder::new();
        alice_store_builder.add_pre_key(IdChoice::Next);
        alice_store_builder.add_signed_pre_key(IdChoice::Next);
        alice_store_builder.add_kyber_pre_key(IdChoice::Next);
        let mut bob_store_builder = TestStoreBuilder::new();
        bob_store_builder.add_pre_key(IdChoice::Next);
        bob_store_builder.add_signed_pre_key(IdChoice::Next);
        bob_store_builder.add_kyber_pre_key(IdChoice::Next);

        let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

        let alice_store = &mut alice_store_builder.store;
        let bob_store = &mut bob_store_builder.store;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let msg = encrypt(alice_store, &bob_address, "this_will_be_a_dup").await?;
        decrypt(bob_store, &alice_address, &msg).await?;
        let err = decrypt(bob_store, &alice_address, &msg)
            .await
            .expect_err("should be a duplicate");
        assert!(matches!(err, SignalProtocolError::DuplicatedMessage(_, _)));
        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_pqr_state_and_message_contents_nonempty() -> TestResult {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_device_id = DeviceId::new(1).unwrap();
        let bob_device_id = DeviceId::new(1).unwrap();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), alice_device_id);
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

        let mut alice_store_builder = TestStoreBuilder::new();
        alice_store_builder.add_pre_key(IdChoice::Next);
        alice_store_builder.add_signed_pre_key(IdChoice::Next);
        alice_store_builder.add_kyber_pre_key(IdChoice::Next);
        let mut bob_store_builder = TestStoreBuilder::new();
        bob_store_builder.add_pre_key(IdChoice::Next);
        bob_store_builder.add_signed_pre_key(IdChoice::Next);
        bob_store_builder.add_kyber_pre_key(IdChoice::Next);

        let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

        let alice_store = &mut alice_store_builder.store;
        let bob_store = &mut bob_store_builder.store;

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let msg = encrypt(alice_store, &bob_address, "msg1").await?;
        assert_matches!(&msg, CiphertextMessage::PreKeySignalMessage(m) if !m.message().pq_ratchet().is_empty());
        decrypt(bob_store, &alice_address, &msg).await?;

        let msg = encrypt(bob_store, &alice_address, "msg2").await?;
        assert_matches!(&msg, CiphertextMessage::SignalMessage(m) if !m.pq_ratchet().is_empty());
        decrypt(alice_store, &bob_address, &msg).await?;

        let msg = encrypt(alice_store, &bob_address, "msg3").await?;
        assert_matches!(&msg, CiphertextMessage::SignalMessage(m) if !m.pq_ratchet().is_empty());

        assert!(!alice_store
            .session_store
            .load_existing_sessions(&[&bob_address])?
            .first()
            .expect("should have Bob's address")
            .current_pq_state()
            .expect("should have Bob's PQ state")
            .is_empty());

        assert!(!bob_store
            .session_store
            .load_existing_sessions(&[&alice_address])?
            .first()
            .expect("should have Alice's address")
            .current_pq_state()
            .expect("should have Alice's PQ state")
            .is_empty());

        Ok(())
    }
    .now_or_never()
    .unwrap()
}

#[test]
fn x3dh_prekey_rejected_as_invalid_message_specifically() {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_device_id = DeviceId::new(1).unwrap();
        let bob_device_id = DeviceId::new(1).unwrap();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), alice_device_id);
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

        let mut bob_store_builder = TestStoreBuilder::new();
        bob_store_builder.add_pre_key(IdChoice::Next);
        bob_store_builder.add_signed_pre_key(IdChoice::Next);
        bob_store_builder.add_kyber_pre_key(IdChoice::Next);

        let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

        let mut alice_store = TestStoreBuilder::new().store;
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("valid");

        let pre_key_message = support::encrypt(&mut alice_store, &bob_address, "bad")
            .await
            .expect("valid");

        let mut bob_one_off_store = bob_store_builder.store.clone();
        _ = support::decrypt(&mut bob_one_off_store, &alice_address, &pre_key_message)
            .await
            .expect("unmodified message is fine");

        let original =
            assert_matches!(pre_key_message, CiphertextMessage::PreKeySignalMessage(m) => m);
        let modified_message = PreKeySignalMessage::new(
            PRE_KYBER_MESSAGE_VERSION.try_into().expect("fits in u8"),
            original.registration_id(),
            original.pre_key_id(),
            original.signed_pre_key_id(),
            None,
            *original.base_key(),
            *original.identity_key(),
            original.message().clone(),
        )
        .expect("valid, though it won't decrypt successfully");

        let err = support::decrypt(
            &mut bob_store_builder.store,
            &alice_address,
            &CiphertextMessage::PreKeySignalMessage(modified_message.clone()),
        )
        .await
        .expect_err("we changed the version, it should be rejected early");
        assert_matches!(
            err,
            SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, msg)
            if msg.contains("X3DH")
        );
    }
    .now_or_never()
    .expect("sync");
}

#[test]
fn x3dh_established_session_is_or_is_not_usable() {
    // We can't actually establish sessions using X3DH anymore. However, we can establish a session
    // using PQXDH and then edit its serialized form to pretend it was established with X3DH.
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_device_id = DeviceId::new(1).unwrap();
        let bob_device_id = DeviceId::new(1).unwrap();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), alice_device_id);
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);

        let mut bob_store_builder = TestStoreBuilder::new();
        bob_store_builder.add_pre_key(IdChoice::Next);
        bob_store_builder.add_signed_pre_key(IdChoice::Next);
        bob_store_builder.add_kyber_pre_key(IdChoice::Next);

        let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

        let mut alice_store = TestStoreBuilder::new().store;
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("valid");

        let pre_key_message = support::encrypt(&mut alice_store, &bob_address, "bad")
            .await
            .expect("valid");

        let bob_store = &mut bob_store_builder.store;
        _ = support::decrypt(bob_store, &alice_address, &pre_key_message)
            .await
            .expect("unmodified message is fine");

        let bob_session_with_alice = bob_store
            .load_session(&alice_address)
            .await
            .expect("can load")
            .expect("has session");
        assert!(
            bob_session_with_alice
                .has_usable_sender_chain(
                    SystemTime::now(),
                    SessionUsabilityRequirements::EstablishedWithPqxdh
                )
                .expect("can check usability")
        );

        let mut serialized_session = bob_session_with_alice.serialize().expect("can serialize");
        let session_version: u8 = bob_session_with_alice
            .session_version()
            .expect("can get session version")
            .try_into()
            .expect("session version still fits in a u8");

        // Check this with `echo '1: 4' | protoscope | xxd`
        const PROTOBUF_FIELD_1_WITH_TYPE_I32: u8 = 0x08;
        let version_as_stored_in_protobuf = [PROTOBUF_FIELD_1_WITH_TYPE_I32, session_version];
        // A quick-and-dirty way to search for a two-value sequence
        // (https://stackoverflow.com/a/35907071). This isn't perfect, but since fields will be
        // serialized in the order they're written in storage.proto, this will in practice actually
        // find the version field in the current session.
        let offset = serialized_session
            .windows(version_as_stored_in_protobuf.len())
            .position(|x| x == version_as_stored_in_protobuf)
            .expect("version stored in protobuf");
        serialized_session[offset + 1] =
            PRE_KYBER_MESSAGE_VERSION.try_into().expect("fits in a u8");

        let reconstituted_session = SessionRecord::deserialize(&serialized_session)
            .expect("edited session is still structurally valid");
        assert_eq!(
            reconstituted_session
                .session_version()
                .expect("can get session version"),
            PRE_KYBER_MESSAGE_VERSION
        );
        assert!(
            reconstituted_session
                .has_usable_sender_chain(SystemTime::now(), SessionUsabilityRequirements::empty())
                .expect("can check usability")
        );
        assert!(
            !reconstituted_session
                .has_usable_sender_chain(
                    SystemTime::now(),
                    SessionUsabilityRequirements::EstablishedWithPqxdh
                )
                .expect("can check usability")
        );
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn prekey_message_sent_from_different_user_is_rejected() {
    async {
        let mut csprng = OsRng.unwrap_err();

        let alice_device_id = DeviceId::new(1).unwrap();
        let bob_device_id = DeviceId::new(1).unwrap();
        let mallory_device_id = DeviceId::new(b'M').unwrap();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), alice_device_id);
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), bob_device_id);
        let mallory_address = ProtocolAddress::new("+14151111113".to_owned(), mallory_device_id);

        let mut bob_store_builder = TestStoreBuilder::new();
        // No one-time EC key here.
        bob_store_builder.add_signed_pre_key(IdChoice::Next);
        bob_store_builder.add_kyber_pre_key(IdChoice::Next);

        let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(bob_device_id);

        let mut alice_store = TestStoreBuilder::new().store;
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await
        .expect("valid");

        let pre_key_message = support::encrypt(&mut alice_store, &bob_address, "bad")
            .await
            .expect("valid");

        let bob_store = &mut bob_store_builder.store;
        _ = support::decrypt(bob_store, &alice_address, &pre_key_message)
            .await
            .expect("unmodified message is fine");
        _ = bob_store
            .load_session(&alice_address)
            .await
            .expect("can load sessions")
            .expect("session successfully created");

        let err = support::decrypt(bob_store, &mallory_address, &pre_key_message)
            .await
            .expect_err("should be rejected");
        assert_matches!(
            err,
            SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, "reused base key")
        );
        assert!(
            bob_store
                .load_session(&mallory_address)
                .await
                .expect("can load sessions")
                .is_none(),
            "should not have created second session"
        )
    }
    .now_or_never()
    .expect("sync")
}
