//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
mod support;

use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use std::convert::TryFrom;
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
        },
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;

            let bob_device_id: DeviceId = 1.into();

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
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
                &mut csprng,
                None,
            )
            .await?;

            assert!(alice_store
                .load_session(&bob_address, None)
                .await?
                .is_some());
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

            assert!(bob_store_builder
                .store
                .load_session(&alice_address, None)
                .await?
                .is_some());
            let bobs_session_with_alice = bob_store_builder
                .store
                .load_session(&alice_address, None)
                .await?
                .expect("session found");
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
                &mut csprng,
                None,
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

            assert!(
                bob_store_builder
                    .store
                    .save_identity(
                        &alice_address,
                        alter_alice_store
                            .get_identity_key_pair(None)
                            .await?
                            .identity_key(),
                        None,
                    )
                    .await?
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
                        .get_identity_key_pair(None)
                        .now_or_never()
                        .expect("sync")
                        .expect("has identity key");
                    content.identity_key = Some(*wrong_identity.identity_key());
                })
                .expect("can reconstruct the bundle");

            assert!(process_prekey_bundle(
                &bob_address,
                &mut alter_alice_store.session_store,
                &mut alter_alice_store.identity_store,
                &bad_bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await
            .is_err());

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
        .with_signed_pre_key(22.into());
    run(&mut alice_store_builder, &mut bob_store_builder)?;

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
            let mut csprng = OsRng;

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
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
                decrypt(&mut bob_store_builder.store, &alice_address, &too_far)
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
        .with_signed_pre_key(22.into());
    run(&mut store_builder_one, &mut store_builder_two)?;

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
            let mut csprng = OsRng;

            let device_id_1: DeviceId = 1.into();
            let a1_address = ProtocolAddress::new("+14151111111".to_owned(), device_id_1);
            let device_id_2: DeviceId = 2.into();
            let a2_address = ProtocolAddress::new("+14151111111".to_owned(), device_id_2);

            let a1_store = &mut a1_store_builder.store;

            let a2_pre_key_bundle = a2_store_builder.make_bundle_with_latest_keys(device_id_2);

            process_prekey_bundle(
                &a2_address,
                &mut a1_store.session_store,
                &mut a1_store.identity_store,
                &a2_pre_key_bundle,
                &mut csprng,
                None,
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
        let mut csprng = OsRng;
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let bob_store_builder = TestStoreBuilder::new()
            .with_pre_key(31337.into())
            .with_signed_pre_key(22.into());

        let good_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

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
                .modify(|mut content| content.ec_pre_key_signature = Some(bad_signature))
                .expect("can recreate the bundle");

            assert!(process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bad_bundle,
                &mut csprng,
                None,
            )
            .await
            .is_err());
        }

        // Finally check that the non-corrupted signature is accepted:
        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &good_bundle,
            &mut csprng,
            None,
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
        .with_signed_pre_key(22.into());
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;
            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            assert!(alice_store
                .load_session(&bob_address, None)
                .await?
                .is_some());
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
        .with_signed_pre_key(22.into());
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());
            let pre_key_id = bob_pre_key_bundle.pre_key_id()?.expect("has pre key id");

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            assert!(alice_store
                .load_session(&bob_address, None)
                .await?
                .is_some());
            assert_eq!(
                alice_store.session_version(&bob_address)?,
                expected_session_version
            );

            let original_message = "L'homme est condamné à être libre";

            assert!(bob_store.get_pre_key(pre_key_id, None).await.is_ok());
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

            assert!(decrypt(bob_store, &alice_address, &incoming_message)
                .await
                .is_err());
            assert!(bob_store.get_pre_key(pre_key_id, None).await.is_ok());

            let incoming_message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(outgoing_message.as_slice())?,
            );

            let ptext = decrypt(bob_store, &alice_address, &incoming_message).await?;

            assert_eq!(
                String::from_utf8(ptext).expect("valid utf8"),
                original_message
            );
            assert!(matches!(
                bob_store.get_pre_key(pre_key_id, None).await.unwrap_err(),
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
    let mut bob_store_builder = TestStoreBuilder::new().with_signed_pre_key(22.into());
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;
            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let alice_store = &mut alice_store_builder.store;

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
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
    let (alice_session, bob_session) = initialize_sessions_v3()?;
    run_session_interaction(alice_session, bob_session)?;

    let (alice_session, bob_session) = initialize_sessions_v4()?;
    run_session_interaction(alice_session, bob_session)?;
    Ok(())
}

#[test]
fn test_message_key_limits() -> TestResult {
    run(initialize_sessions_v3()?)?;
    run(initialize_sessions_v4()?)?;

    fn run(sessions: (SessionRecord, SessionRecord)) -> TestResult {
        async {
            let (alice_session_record, bob_session_record) = sessions;

            let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

            let mut alice_store = TestStoreBuilder::new().store;
            let mut bob_store = TestStoreBuilder::new().store;

            alice_store
                .store_session(&bob_address, &alice_session_record, None)
                .await?;
            bob_store
                .store_session(&alice_address, &bob_session_record, None)
                .await?;

            const MAX_MESSAGE_KEYS: usize = 2000; // same value as in library
            const TOO_MANY_MESSAGES: usize = MAX_MESSAGE_KEYS + 300;

            let mut inflight = Vec::with_capacity(TOO_MANY_MESSAGES);

            for i in 0..TOO_MANY_MESSAGES {
                inflight.push(
                    encrypt(&mut alice_store, &bob_address, &format!("It's over {}", i)).await?,
                );
            }

            assert_eq!(
                String::from_utf8(decrypt(&mut bob_store, &alice_address, &inflight[1000]).await?)
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
        .with_signed_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let alice_pre_key_bundle = alice_store_builder.make_bundle_with_latest_keys(1.into());
            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                &mut csprng,
                None,
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
        .with_signed_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let alice_pre_key_bundle = alice_store_builder.make_bundle_with_latest_keys(1.into());
            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                &mut csprng,
                None,
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
        .with_signed_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let alice_pre_key_bundle = alice_store_builder.make_bundle_with_latest_keys(1.into());
            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

            let alice_store = &mut alice_store_builder.store;
            let bob_store = &mut bob_store_builder.store;

            process_prekey_bundle(
                &bob_address,
                &mut alice_store.session_store,
                &mut alice_store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
            )
            .await?;

            process_prekey_bundle(
                &alice_address,
                &mut bob_store.session_store,
                &mut bob_store.identity_store,
                &alice_pre_key_bundle,
                &mut csprng,
                None,
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
        .with_signed_pre_key(IdChoice::Random);
    let mut bob_store_builder = TestStoreBuilder::new()
        .with_pre_key(IdChoice::Random)
        .with_signed_pre_key(IdChoice::Random);
    run(
        &mut alice_store_builder,
        &mut bob_store_builder,
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            for _ in 0..15 {
                let alice_pre_key_bundle =
                    alice_store_builder.make_bundle_with_latest_keys(1.into());
                let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store_builder.store.session_store,
                    &mut alice_store_builder.store.identity_store,
                    &bob_pre_key_bundle,
                    &mut csprng,
                    None,
                )
                .await?;

                process_prekey_bundle(
                    &alice_address,
                    &mut bob_store_builder.store.session_store,
                    &mut bob_store_builder.store.identity_store,
                    &alice_pre_key_bundle,
                    &mut csprng,
                    None,
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
        },
        PRE_KYBER_MESSAGE_VERSION,
    )?;

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
            let mut csprng = OsRng;

            let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
            let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

            let mut alice_store_builder = TestStoreBuilder::new();
            add_keys(&mut alice_store_builder);
            let mut bob_store_builder = TestStoreBuilder::new();
            add_keys(&mut bob_store_builder);

            let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

            process_prekey_bundle(
                &bob_address,
                &mut alice_store_builder.store.session_store,
                &mut alice_store_builder.store.identity_store,
                &bob_pre_key_bundle,
                &mut csprng,
                None,
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
                    alice_store_builder.make_bundle_with_latest_keys((i + 2).into());
                let bob_pre_key_bundle =
                    bob_store_builder.make_bundle_with_latest_keys((i + 2).into());

                process_prekey_bundle(
                    &bob_address,
                    &mut alice_store_builder.store.session_store,
                    &mut alice_store_builder.store.identity_store,
                    &bob_pre_key_bundle,
                    &mut csprng,
                    None,
                )
                .await?;

                process_prekey_bundle(
                    &alice_address,
                    &mut bob_store_builder.store.session_store,
                    &mut bob_store_builder.store.identity_store,
                    &alice_pre_key_bundle,
                    &mut csprng,
                    None,
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
                        &bob_address
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
                        &bob_address
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
                        &bob_address
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
                        &bob_address
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
                    &bob_address
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
                    &alice_address
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
                    &alice_address
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
                    &alice_address
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
        let mut csprng = OsRng;
        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14151111112".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store_builder = TestStoreBuilder::new()
            .with_pre_key(0.into())
            .with_signed_pre_key(0.into())
            .with_kyber_pre_key(0.into());

        let bob_pre_key_bundle = bob_store_builder.make_bundle_with_latest_keys(1.into());

        process_prekey_bundle(
            &bob_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut csprng,
            None,
        )
        .await?;

        assert_eq!(
            alice_store
                .load_session(&bob_address, None)
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

#[allow(clippy::needless_range_loop)]
fn run_session_interaction(alice_session: SessionRecord, bob_session: SessionRecord) -> TestResult {
    async {
        use rand::seq::SliceRandom;

        let alice_address = ProtocolAddress::new("+14159999999".to_owned(), 1.into());
        let bob_address = ProtocolAddress::new("+14158888888".to_owned(), 1.into());

        let mut alice_store = TestStoreBuilder::new().store;
        let mut bob_store = TestStoreBuilder::new().store;

        alice_store
            .store_session(&bob_address, &alice_session, None)
            .await?;
        bob_store
            .store_session(&alice_address, &bob_session, None)
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
            let ptext = format!("смерть за смерть {}", i);
            let ctext = encrypt(&mut alice_store, &bob_address, &ptext).await?;
            alice_messages.push((ptext, ctext));
        }

        let mut rng = rand::rngs::OsRng;

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
            let ptext = format!("Relax in the safety of your own delusions. {}", i);
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
        let alice_ptext = format!("A->B message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message {}", i);
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
        let alice_ptext = format!("A->B OOO message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        alice_ooo_messages.push((alice_ptext, alice_message));
    }

    for i in 0..10 {
        let alice_ptext = format!("A->B post-OOO message {}", i);
        let alice_message = encrypt(alice_store, bob_address, &alice_ptext).await?;
        assert_eq!(alice_message.message_type(), CiphertextMessageType::Whisper);
        assert_eq!(
            String::from_utf8(decrypt(bob_store, alice_address, &alice_message).await?)
                .expect("valid utf8"),
            alice_ptext
        );
    }

    for i in 0..10 {
        let bob_ptext = format!("B->A message post-OOO {}", i);
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

async fn is_session_id_equal(
    alice_store: &dyn ProtocolStore,
    alice_address: &ProtocolAddress,
    bob_store: &dyn ProtocolStore,
    bob_address: &ProtocolAddress,
) -> Result<bool, SignalProtocolError> {
    Ok(alice_store
        .load_session(bob_address, None)
        .await?
        .expect("session found")
        .alice_base_key()?
        == bob_store
            .load_session(alice_address, None)
            .await?
            .expect("session found")
            .alice_base_key()?)
}
