//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod support;
use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use support::*;
use uuid::Uuid;

#[test]
fn test_server_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let serialized = server_cert.serialized()?.to_vec();

    let recovered = ServerCertificate::deserialize(&serialized)?;

    assert!(recovered.validate(&trust_root.public_key)?);

    let mut cert_data = serialized;
    let cert_bits = cert_data.len() * 8;

    for b in 0..cert_bits {
        cert_data[b / 8] ^= 1u8 << (b % 8); // flip a bit
        let cert = ServerCertificate::deserialize(&cert_data);
        cert_data[b / 8] ^= 1u8 << (b % 8); // flip the bit back

        match cert {
            Ok(cert) => {
                assert!(!cert.validate(&trust_root.public_key)?);
            }
            Err(e) => match e {
                SignalProtocolError::InvalidProtobufEncoding
                | SignalProtocolError::BadKeyType(_)
                | SignalProtocolError::BadKeyLength(_, _) => {}

                unexpected_err => {
                    panic!("unexpected error {:?}", unexpected_err)
                }
            },
        }
    }

    Ok(())
}

#[test]
fn test_revoked_server_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let revoked_id = 0xDEADC357;

    let server_cert = ServerCertificate::new(
        revoked_id,
        server_key.public_key,
        &trust_root.private_key,
        &mut rng,
    )?;

    let serialized = server_cert.serialized()?.to_vec();

    let recovered = ServerCertificate::deserialize(&serialized)?;

    assert!(!recovered.validate(&trust_root.public_key)?);

    Ok(())
}

#[test]
fn test_sender_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);
    let key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let device_id: DeviceId = 42.into();
    let expires = Timestamp::from_epoch_millis(1605722925);

    let sender_cert = SenderCertificate::new(
        "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string(),
        Some("+14152222222".to_string()),
        key.public_key,
        device_id,
        expires,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )?;

    assert!(sender_cert.validate(&trust_root.public_key, expires)?);
    assert!(!sender_cert.validate(&trust_root.public_key, expires.add_millis(1))?); // expired

    let mut sender_cert_data = sender_cert.serialized()?.to_vec();
    let sender_cert_bits = sender_cert_data.len() * 8;

    for b in 0..sender_cert_bits {
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip a bit
        let cert = SenderCertificate::deserialize(&sender_cert_data);
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip the bit back

        match cert {
            Ok(cert) => {
                assert!(!cert.validate(&trust_root.public_key, expires)?);
            }
            Err(e) => match e {
                SignalProtocolError::InvalidProtobufEncoding
                | SignalProtocolError::BadKeyLength(_, _)
                | SignalProtocolError::BadKeyType(_) => {}

                unexpected_err => {
                    panic!("unexpected error {:?}", unexpected_err)
                }
            },
        }
    }

    Ok(())
}

#[test]
fn test_sealed_sender() -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();
        let bob_e164 = "+14151114444".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let alice_ptext = vec![1, 2, 3, 23, 99];
        let alice_ctext = sealed_sender_encrypt(
            &bob_uuid_address,
            &sender_cert,
            &alice_ptext,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &trust_root.public_key,
            expires.sub_millis(1),
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
        )
        .await?;

        assert_eq!(bob_ptext.message, alice_ptext);
        assert_eq!(bob_ptext.sender_uuid, alice_uuid);
        assert_eq!(bob_ptext.sender_e164, Some(alice_e164));
        assert_eq!(bob_ptext.device_id, alice_device_id);

        // Now test but with an expired cert:

        let alice_ctext = sealed_sender_encrypt(
            &bob_uuid_address,
            &sender_cert,
            &alice_ptext,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &trust_root.public_key,
            expires.add_millis(11),
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        // Now test but try to verify using some other trust root

        let alice_ctext = sealed_sender_encrypt(
            &bob_uuid_address,
            &sender_cert,
            &alice_ptext,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let wrong_trust_root = KeyPair::generate(&mut rng);

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &wrong_trust_root.public_key,
            expires.sub_millis(1),
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_sender_key_in_sealed_sender() -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let device_id: DeviceId = 1.into();
        let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), device_id);
        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let distribution_message = create_sender_key_distribution_message(
            &alice_uuid_address,
            distribution_id,
            &mut alice_store,
            &mut rng,
        )
        .await?;

        process_sender_key_distribution_message(
            &alice_uuid_address,
            &distribution_message,
            &mut bob_store,
        )
        .await?;

        let alice_message = group_encrypt(
            &mut alice_store,
            &alice_uuid_address,
            distribution_id,
            "swim camp".as_bytes(),
            &mut rng,
        )
        .await?;
        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_cert.clone(),
            alice_message.serialized().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let alice_ctext = sealed_sender_encrypt_from_usmc(
            &bob_uuid_address,
            &alice_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await?;

        let bob_usmc =
            sealed_sender_decrypt_to_usmc(&alice_ctext, &bob_store.identity_store).await?;

        assert!(matches!(
            bob_usmc.msg_type()?,
            CiphertextMessageType::SenderKey,
        ));

        let bob_plaintext =
            group_decrypt(bob_usmc.contents()?, &mut bob_store, &alice_uuid_address).await?;

        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid UTF-8"),
            "swim camp"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_sealed_sender_multi_recipient() -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();
        let bob_e164 = "+14151114444".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let alice_ptext = vec![1, 2, 3, 23, 99];
        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let recipients = [&bob_uuid_address];
        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await?;

        let (recipient_addr, bob_ctext) = extract_single_ssv2_received_message(&alice_ctext);
        assert_eq!(recipient_addr.service_id_string(), bob_uuid);
        assert_eq!(bob_ctext[0], 0x22); // Use the original SSv2 version byte.

        let bob_ptext = sealed_sender_decrypt(
            &bob_ctext,
            &trust_root.public_key,
            expires.sub_millis(1),
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
        )
        .await?;

        assert_eq!(bob_ptext.message, alice_ptext);
        assert_eq!(bob_ptext.sender_uuid, alice_uuid);
        assert_eq!(bob_ptext.sender_e164, Some(alice_e164));
        assert_eq!(bob_ptext.device_id, alice_device_id);

        // Check the original SSv2 upload format too.
        // libsignal doesn't support encoding it, so we're going to hand-edit.
        let mut alice_ctext_old_format = alice_ctext;
        alice_ctext_old_format[0] = 0x22; // Update the version.
        assert_eq!(alice_ctext_old_format.remove(2), 0); // Check that we have the right byte.

        let (recipient_addr_old_format, bob_ctext_old_format) =
            extract_single_ssv2_received_message(&alice_ctext_old_format);
        assert_eq!(recipient_addr_old_format, recipient_addr);
        assert_eq!(bob_ctext_old_format[0], alice_ctext_old_format[0]);
        assert_eq!(&bob_ctext_old_format[1..], &bob_ctext[1..]);

        // Now test but with an expired cert:
        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let recipients = [&bob_uuid_address];
        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await?;

        let (_, bob_ctext) = extract_single_ssv2_received_message(&alice_ctext);

        let bob_ptext = sealed_sender_decrypt(
            &bob_ctext,
            &trust_root.public_key,
            expires.add_millis(11),
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        // Now test but try to verify using some other trust root

        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let recipients = [&bob_uuid_address];
        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await?;

        let wrong_trust_root = KeyPair::generate(&mut rng);

        let (_, bob_ctext) = extract_single_ssv2_received_message(&alice_ctext);

        let bob_ptext = sealed_sender_decrypt(
            &bob_ctext,
            &wrong_trust_root.public_key,
            expires.sub_millis(1),
            Some(bob_e164.clone()),
            bob_uuid.clone(),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &bob_store.signed_pre_key_store,
            &mut bob_store.kyber_pre_key_store,
        )
        .await;

        match bob_ptext {
            Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => { /* ok */ }
            Err(err) => {
                panic!("Unexpected error {}", err)
            }
            Ok(_) => {
                panic!("Shouldn't have decrypted")
            }
        }

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_sealed_sender_multi_recipient_encrypt_with_archived_session(
) -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let alice_ptext = vec![1, 2, 3, 23, 99];
        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let recipients = [&bob_uuid_address];
        let mut session = alice_store
            .session_store
            .load_session(&bob_uuid_address)
            .await?
            .expect("present");
        session.archive_current_state()?;
        match sealed_sender_multi_recipient_encrypt(
            &recipients,
            &[&session],
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await
        {
            Ok(_) => panic!("should have failed"),
            Err(e) => {
                // Make sure we mention *which* recipient's session failed.
                let description = e.to_string();
                assert!(
                    description.contains(&bob_uuid_address.to_string()),
                    "should mention recipient in message \"{}\"",
                    description
                );
            }
        }

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_sealed_sender_multi_recipient_encrypt_with_bad_registration_id(
) -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng;

        let alice_device_id = 23;
        let bob_device_id = 42;

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id.into());

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store =
            InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), 0x4000)?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id.into(),
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        let alice_ptext = vec![1, 2, 3, 23, 99];
        let alice_message = message_encrypt(
            &alice_ptext,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            SystemTime::now(),
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            alice_message.message_type(),
            sender_cert.clone(),
            alice_message.serialize().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let recipients = [&bob_uuid_address];
        match sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await
        {
            Ok(_) => panic!("should have failed"),
            Err(SignalProtocolError::InvalidRegistrationId(address, _id)) => {
                assert_eq!(address, bob_uuid_address);
            }
            Err(e) => panic!("wrong error: {}", e),
        }

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn test_decryption_error_in_sealed_sender() -> Result<(), SignalProtocolError> {
    async {
        let mut rng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), 1.into());
        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let alice_pre_key_bundle = create_pre_key_bundle(&mut alice_store, &mut rng).await?;

        process_prekey_bundle(
            &alice_uuid_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            &alice_pre_key_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        // Send one message to establish a session.

        let bob_first_message = message_encrypt(
            b"swim camp",
            &alice_uuid_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            SystemTime::now(),
        )
        .await?;

        message_decrypt(
            &bob_first_message,
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &mut alice_store.pre_key_store,
            &alice_store.signed_pre_key_store,
            &mut alice_store.kyber_pre_key_store,
            &mut rng,
        )
        .await?;

        // Pretend the second message fails to decrypt.

        let bob_message = message_encrypt(
            b"space camp",
            &alice_uuid_address,
            &mut bob_store.session_store,
            &mut bob_store.identity_store,
            SystemTime::now(),
        )
        .await?;

        let original_ratchet_key = match bob_message {
            CiphertextMessage::PreKeySignalMessage(ref m) => m.message().sender_ratchet_key(),
            _ => panic!("without ACKs, every message should be a PreKeySignalMessage"),
        };

        // Skip over the part where Bob sends this to Alice and Alice fails to decrypt it,
        // for whatever reason.

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        const ORIGINAL_TIMESTAMP: Timestamp = Timestamp::from_epoch_millis(408);
        let error_message = DecryptionErrorMessage::for_original(
            bob_message.serialize(),
            bob_message.message_type(),
            ORIGINAL_TIMESTAMP,
            5,
        )?;
        let error_message_content = PlaintextContent::from(error_message);
        let error_message_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::Plaintext,
            sender_cert.clone(),
            error_message_content.serialized().to_vec(),
            ContentHint::Default,
            None,
        )?;

        let alice_ctext = sealed_sender_encrypt_from_usmc(
            &bob_uuid_address,
            &error_message_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await?;

        let bob_usmc =
            sealed_sender_decrypt_to_usmc(&alice_ctext, &bob_store.identity_store).await?;

        assert!(matches!(
            bob_usmc.msg_type()?,
            CiphertextMessageType::Plaintext,
        ));

        let bob_plaintext = PlaintextContent::try_from(bob_usmc.contents()?)?;
        let bob_error_message =
            extract_decryption_error_message_from_serialized_content(bob_plaintext.body())
                .expect("present");

        assert_eq!(bob_error_message.ratchet_key(), Some(original_ratchet_key));
        assert_eq!(bob_error_message.timestamp(), ORIGINAL_TIMESTAMP);
        assert_eq!(bob_error_message.device_id(), 5);

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn parse_empty_multi_recipient_sealed_sender() {
    assert!(SealedSenderV2SentMessage::parse(&[]).is_err());
}

#[test]
fn test_sealed_sender_multi_recipient_redundant_empty_devices() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut csprng);
        let server_key = KeyPair::generate(&mut csprng);

        let server_cert = ServerCertificate::new(
            1,
            server_key.public_key,
            &trust_root.private_key,
            &mut csprng,
        )?;

        let expires = Timestamp::from_epoch_millis(1605722925);

        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            None,
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut csprng,
        )?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_cert.clone(),
            vec![],
            ContentHint::Implicit,
            Some([42].to_vec()),
        )?;

        let recipients = [&bob_uuid_address];
        let recipient_excluded_and_included = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [ServiceId::parse_from_service_id_string(&bob_uuid).unwrap()],
            &alice_usmc,
            &alice_store.identity_store,
            &mut csprng,
        )
        .await?;
        assert!(SealedSenderV2SentMessage::parse(&recipient_excluded_and_included).is_err());

        let recipient_excluded_twice = sealed_sender_multi_recipient_encrypt(
            &[],
            &[],
            [
                ServiceId::parse_from_service_id_string(&bob_uuid).unwrap(),
                ServiceId::parse_from_service_id_string(&bob_uuid).unwrap(),
            ],
            &alice_usmc,
            &alice_store.identity_store,
            &mut csprng,
        )
        .await?;
        assert!(SealedSenderV2SentMessage::parse(&recipient_excluded_twice).is_err());

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}
