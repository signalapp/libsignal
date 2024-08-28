//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod support;

use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use support::*;
use uuid::Uuid;

#[test]
fn group_no_send_session() -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;

    let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
    let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

    let mut alice_store = test_in_memory_protocol_store()?;

    assert!(group_encrypt(
        &mut alice_store,
        &sender_address,
        distribution_id,
        "space camp?".as_bytes(),
        &mut csprng,
    )
    .now_or_never()
    .expect("sync")
    .is_err());

    Ok(())
}

#[test]
fn group_no_recv_session() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let device_id: DeviceId = 1.into();
        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), device_id);
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let _recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        let alice_ciphertext = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "space camp?".as_bytes(),
            &mut csprng,
        )
        .await?;

        let bob_plaintext = group_decrypt(
            alice_ciphertext.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await;

        assert!(bob_plaintext.is_err());

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_basic_encrypt_decrypt() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        let alice_ciphertext = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "space camp?".as_bytes(),
            &mut csprng,
        )
        .await?;

        process_sender_key_distribution_message(
            &sender_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        let bob_plaintext = group_decrypt(
            alice_ciphertext.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await?;

        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "space camp?"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_sealed_sender() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();
        let carol_device_id: DeviceId = 1.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();
        let carol_uuid = "38381c3b-2606-4ca7-9310-7cb927f2ab4a".to_string();

        let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), alice_device_id);
        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);
        let carol_uuid_address = ProtocolAddress::new(carol_uuid.clone(), carol_device_id);

        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;
        let mut carol_store = support::test_in_memory_protocol_store()?;

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;
        let carol_pre_key_bundle = create_pre_key_bundle(&mut carol_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        process_prekey_bundle(
            &carol_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &carol_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &alice_uuid_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;
        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut carol_store,
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
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut csprng,
        )?;

        let alice_message = group_encrypt(
            &mut alice_store,
            &alice_uuid_address,
            distribution_id,
            "space camp?".as_bytes(),
            &mut csprng,
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_cert.clone(),
            alice_message.serialized().to_vec(),
            ContentHint::Implicit,
            Some([42].to_vec()),
        )?;

        let recipients = [&bob_uuid_address, &carol_uuid_address];
        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut csprng,
        )
        .await?;

        let alice_ctext_parsed = SealedSenderV2SentMessage::parse(&alice_ctext)?;
        assert_eq!(alice_ctext_parsed.recipients.len(), 2);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(0)
                .expect("checked length")
                .0
                .service_id_string(),
            bob_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[0].devices.len(), 1);
        assert_eq!(alice_ctext_parsed.recipients[0].devices[0].0, bob_device_id);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(1)
                .expect("checked length")
                .0
                .service_id_string(),
            carol_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[1].devices.len(), 1);
        assert_eq!(
            alice_ctext_parsed.recipients[1].devices[0].0,
            carol_device_id
        );

        let bob_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[0])
            .as_ref()
            .concat();
        let carol_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[1])
            .as_ref()
            .concat();

        let bob_usmc = sealed_sender_decrypt_to_usmc(&bob_ctext, &bob_store.identity_store).await?;

        assert_eq!(bob_usmc.sender()?.sender_uuid()?, alice_uuid);
        assert_eq!(bob_usmc.sender()?.sender_e164()?, Some(alice_e164.as_ref()));
        assert_eq!(bob_usmc.sender()?.sender_device_id()?, alice_device_id);
        assert_eq!(bob_usmc.content_hint()?, ContentHint::Implicit);
        assert_eq!(bob_usmc.group_id()?, Some(&[42][..]));

        let bob_plaintext =
            group_decrypt(bob_usmc.contents()?, &mut bob_store, &alice_uuid_address).await?;

        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "space camp?"
        );

        let carol_usmc =
            sealed_sender_decrypt_to_usmc(&carol_ctext, &carol_store.identity_store).await?;

        assert_eq!(carol_usmc.serialized()?, bob_usmc.serialized()?);

        let carol_plaintext = group_decrypt(
            carol_usmc.contents()?,
            &mut carol_store,
            &alice_uuid_address,
        )
        .await?;

        assert_eq!(
            String::from_utf8(carol_plaintext).expect("valid utf8"),
            "space camp?"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_sealed_sender_multiple_devices() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();
        let carol_device_id: DeviceId = 1.into();
        let carol2_device_id: DeviceId = 2.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();
        let carol_uuid = "38381c3b-2606-4ca7-9310-7cb927f2ab4a".to_string();

        let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), alice_device_id);
        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);
        let carol_uuid_address = ProtocolAddress::new(carol_uuid.clone(), carol_device_id);
        let carol2_uuid_address = ProtocolAddress::new(carol_uuid.clone(), carol2_device_id);

        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;
        let mut carol_store = support::test_in_memory_protocol_store()?;
        let mut carol2_store = support::test_in_memory_protocol_store()?;
        // Make sure we use the same identity key, like a real linked device.
        carol2_store.identity_store = InMemIdentityKeyStore::new(
            carol_store.get_identity_key_pair().await?,
            carol2_store.get_local_registration_id().await?,
        );

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;
        let carol_pre_key_bundle = create_pre_key_bundle(&mut carol_store, &mut csprng).await?;
        let carol2_pre_key_bundle = create_pre_key_bundle(&mut carol2_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        process_prekey_bundle(
            &carol_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &carol_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        process_prekey_bundle(
            &carol2_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &carol2_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &alice_uuid_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;
        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut carol_store,
        )
        .await?;
        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut carol2_store,
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
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut csprng,
        )?;

        let alice_message = group_encrypt(
            &mut alice_store,
            &alice_uuid_address,
            distribution_id,
            "space camp?".as_bytes(),
            &mut csprng,
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_cert.clone(),
            alice_message.serialized().to_vec(),
            ContentHint::Implicit,
            Some([42].to_vec()),
        )?;

        let recipients = [&bob_uuid_address, &carol_uuid_address, &carol2_uuid_address];
        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [],
            &alice_usmc,
            &alice_store.identity_store,
            &mut csprng,
        )
        .await?;

        let alice_ctext_parsed = SealedSenderV2SentMessage::parse(&alice_ctext)?;
        assert_eq!(alice_ctext_parsed.recipients.len(), 2);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(0)
                .expect("checked length")
                .0
                .service_id_string(),
            bob_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[0].devices.len(), 1);
        assert_eq!(alice_ctext_parsed.recipients[0].devices[0].0, bob_device_id);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(1)
                .expect("checked length")
                .0
                .service_id_string(),
            carol_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[1].devices.len(), 2);
        assert_eq!(
            alice_ctext_parsed.recipients[1].devices[0].0,
            carol_device_id
        );
        assert_eq!(
            alice_ctext_parsed.recipients[1].devices[1].0,
            carol2_device_id
        );

        let bob_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[0])
            .as_ref()
            .concat();
        let carol_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[1])
            .as_ref()
            .concat();

        let bob_usmc = sealed_sender_decrypt_to_usmc(&bob_ctext, &bob_store.identity_store).await?;

        assert_eq!(bob_usmc.sender()?.sender_uuid()?, alice_uuid);
        assert_eq!(bob_usmc.sender()?.sender_e164()?, Some(alice_e164.as_ref()));
        assert_eq!(bob_usmc.sender()?.sender_device_id()?, alice_device_id);
        assert_eq!(bob_usmc.content_hint()?, ContentHint::Implicit);
        assert_eq!(bob_usmc.group_id()?, Some(&[42][..]));

        let bob_plaintext =
            group_decrypt(bob_usmc.contents()?, &mut bob_store, &alice_uuid_address).await?;

        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "space camp?"
        );

        let carol_usmc =
            sealed_sender_decrypt_to_usmc(&carol_ctext, &carol_store.identity_store).await?;

        assert_eq!(carol_usmc.serialized()?, bob_usmc.serialized()?);

        let carol_plaintext = group_decrypt(
            carol_usmc.contents()?,
            &mut carol_store,
            &alice_uuid_address,
        )
        .await?;

        assert_eq!(
            String::from_utf8(carol_plaintext).expect("valid utf8"),
            "space camp?"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_sealed_sender_multiple_devices_and_excluded_recipients() -> Result<(), SignalProtocolError>
{
    async {
        let mut csprng = OsRng;

        let alice_device_id: DeviceId = 23.into();
        let bob_device_id: DeviceId = 42.into();
        let carol_device_id: DeviceId = 1.into();
        let carol2_device_id: DeviceId = 2.into();

        let alice_e164 = "+14151111111".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();
        let carol_uuid = "38381c3b-2606-4ca7-9310-7cb927f2ab4a".to_string();
        let dave_uuid = "d4c8dd1f-89d8-484f-8e38-5aa6a1c2180b".to_string();
        let erin_uuid = "726e0b5d-2253-4f56-a02f-7317541a5b3c".to_string();

        let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), alice_device_id);
        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);
        let carol_uuid_address = ProtocolAddress::new(carol_uuid.clone(), carol_device_id);
        let carol2_uuid_address = ProtocolAddress::new(carol_uuid.clone(), carol2_device_id);

        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = support::test_in_memory_protocol_store()?;
        let mut bob_store = support::test_in_memory_protocol_store()?;
        let mut carol_store = support::test_in_memory_protocol_store()?;
        let mut carol2_store = support::test_in_memory_protocol_store()?;
        // Make sure we use the same identity key, like a real linked device.
        carol2_store.identity_store = InMemIdentityKeyStore::new(
            carol_store.get_identity_key_pair().await?,
            carol2_store.get_local_registration_id().await?,
        );

        let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut csprng).await?;
        let carol_pre_key_bundle = create_pre_key_bundle(&mut carol_store, &mut csprng).await?;
        let carol2_pre_key_bundle = create_pre_key_bundle(&mut carol2_store, &mut csprng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        process_prekey_bundle(
            &carol_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &carol_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        process_prekey_bundle(
            &carol2_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &carol2_pre_key_bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &alice_uuid_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;
        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut carol_store,
        )
        .await?;
        process_sender_key_distribution_message(
            &alice_uuid_address,
            &recv_distribution_message,
            &mut carol2_store,
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
            Some(alice_e164.clone()),
            alice_pubkey,
            alice_device_id,
            expires,
            server_cert,
            &server_key.private_key,
            &mut csprng,
        )?;

        let alice_message = group_encrypt(
            &mut alice_store,
            &alice_uuid_address,
            distribution_id,
            "space camp?".as_bytes(),
            &mut csprng,
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_cert.clone(),
            alice_message.serialized().to_vec(),
            ContentHint::Implicit,
            Some([42].to_vec()),
        )?;

        let recipients = [&bob_uuid_address, &carol_uuid_address, &carol2_uuid_address];
        let alice_ctext = sealed_sender_multi_recipient_encrypt(
            &recipients,
            &alice_store
                .session_store
                .load_existing_sessions(&recipients)?,
            [
                ServiceId::parse_from_service_id_string(&dave_uuid).unwrap(),
                ServiceId::parse_from_service_id_string(&erin_uuid).unwrap(),
            ],
            &alice_usmc,
            &alice_store.identity_store,
            &mut csprng,
        )
        .await?;

        let alice_ctext_parsed = SealedSenderV2SentMessage::parse(&alice_ctext)?;
        assert_eq!(alice_ctext_parsed.recipients.len(), 4);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(0)
                .expect("checked length")
                .0
                .service_id_string(),
            bob_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[0].devices.len(), 1);
        assert_eq!(alice_ctext_parsed.recipients[0].devices[0].0, bob_device_id);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(1)
                .expect("checked length")
                .0
                .service_id_string(),
            carol_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[1].devices.len(), 2);
        assert_eq!(
            alice_ctext_parsed.recipients[1].devices[0].0,
            carol_device_id
        );
        assert_eq!(
            alice_ctext_parsed.recipients[1].devices[1].0,
            carol2_device_id
        );
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(2)
                .expect("checked length")
                .0
                .service_id_string(),
            dave_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[2].devices.len(), 0);
        assert_eq!(
            alice_ctext_parsed
                .recipients
                .get_index(3)
                .expect("checked length")
                .0
                .service_id_string(),
            erin_uuid
        );
        assert_eq!(alice_ctext_parsed.recipients[3].devices.len(), 0);

        let bob_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[0])
            .as_ref()
            .concat();
        let carol_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[1])
            .as_ref()
            .concat();
        // This isn't really necessary, but just make sure it doesn't crash.
        let _dave_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[2])
            .as_ref()
            .concat();
        let _erin_ctext = alice_ctext_parsed
            .received_message_parts_for_recipient(&alice_ctext_parsed.recipients[3])
            .as_ref()
            .concat();

        let bob_usmc = sealed_sender_decrypt_to_usmc(&bob_ctext, &bob_store.identity_store).await?;

        assert_eq!(bob_usmc.sender()?.sender_uuid()?, alice_uuid);
        assert_eq!(bob_usmc.sender()?.sender_e164()?, Some(alice_e164.as_ref()));
        assert_eq!(bob_usmc.sender()?.sender_device_id()?, alice_device_id);
        assert_eq!(bob_usmc.content_hint()?, ContentHint::Implicit);
        assert_eq!(bob_usmc.group_id()?, Some(&[42][..]));

        let bob_plaintext =
            group_decrypt(bob_usmc.contents()?, &mut bob_store, &alice_uuid_address).await?;

        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "space camp?"
        );

        let carol_usmc =
            sealed_sender_decrypt_to_usmc(&carol_ctext, &carol_store.identity_store).await?;

        assert_eq!(carol_usmc.serialized()?, bob_usmc.serialized()?);

        let carol_plaintext = group_decrypt(
            carol_usmc.contents()?,
            &mut carol_store,
            &alice_uuid_address,
        )
        .await?;

        assert_eq!(
            String::from_utf8(carol_plaintext).expect("valid utf8"),
            "space camp?"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_large_messages() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        let mut large_message: Vec<u8> = Vec::with_capacity(1024);
        for _ in 0..large_message.capacity() {
            large_message.push(csprng.gen());
        }

        let alice_ciphertext = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            &large_message,
            &mut csprng,
        )
        .await?;

        process_sender_key_distribution_message(
            &sender_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        let bob_plaintext = group_decrypt(
            alice_ciphertext.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await?;

        assert_eq!(bob_plaintext, large_message);

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_basic_ratchet() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        process_sender_key_distribution_message(
            &sender_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        let alice_ciphertext1 = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "swim camp".as_bytes(),
            &mut csprng,
        )
        .await?;
        let alice_ciphertext2 = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "robot camp".as_bytes(),
            &mut csprng,
        )
        .await?;
        let alice_ciphertext3 = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "ninja camp".as_bytes(),
            &mut csprng,
        )
        .await?;

        let bob_plaintext1 = group_decrypt(
            alice_ciphertext1.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext1).expect("valid utf8"),
            "swim camp"
        );

        assert!(matches!(
            group_decrypt(
                alice_ciphertext1.serialized(),
                &mut bob_store,
                &sender_address,
            )
            .await,
            Err(SignalProtocolError::DuplicatedMessage(1, 0))
        ));

        let bob_plaintext3 = group_decrypt(
            alice_ciphertext3.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext3).expect("valid utf8"),
            "ninja camp"
        );

        let bob_plaintext2 = group_decrypt(
            alice_ciphertext2.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext2).expect("valid utf8"),
            "robot camp"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_late_join() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        for i in 0..100 {
            group_encrypt(
                &mut alice_store,
                &sender_address,
                distribution_id,
                format!("nefarious plotting {}/100", i).as_bytes(),
                &mut csprng,
            )
            .await?;
        }

        // now bob joins:
        process_sender_key_distribution_message(
            &sender_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        let alice_ciphertext = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "welcome bob".as_bytes(),
            &mut csprng,
        )
        .await?;

        let bob_plaintext = group_decrypt(
            alice_ciphertext.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await?;
        assert_eq!(
            String::from_utf8(bob_plaintext).expect("valid utf8"),
            "welcome bob"
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_out_of_order() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        process_sender_key_distribution_message(
            &sender_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        let mut ciphertexts = Vec::with_capacity(100);

        for i in 0..ciphertexts.capacity() {
            ciphertexts.push(
                group_encrypt(
                    &mut alice_store,
                    &sender_address,
                    distribution_id,
                    format!("nefarious plotting {:02}/100", i).as_bytes(),
                    &mut csprng,
                )
                .await?,
            );
        }

        ciphertexts.shuffle(&mut csprng);

        let mut plaintexts = Vec::with_capacity(ciphertexts.len());

        for ciphertext in ciphertexts {
            plaintexts.push(
                group_decrypt(ciphertext.serialized(), &mut bob_store, &sender_address).await?,
            );
        }

        plaintexts.sort();

        for (i, plaintext) in plaintexts.iter().enumerate() {
            assert_eq!(
                String::from_utf8(plaintext.to_vec()).expect("valid utf8"),
                format!("nefarious plotting {:02}/100", i)
            );
        }

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
#[ignore = "slow to run locally"]
fn group_too_far_in_the_future() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        process_sender_key_distribution_message(
            &sender_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        for i in 0..25001 {
            group_encrypt(
                &mut alice_store,
                &sender_address,
                distribution_id,
                format!("nefarious plotting {}", i).as_bytes(),
                &mut csprng,
            )
            .await?;
        }

        let alice_ciphertext = group_encrypt(
            &mut alice_store,
            &sender_address,
            distribution_id,
            "you got the plan?".as_bytes(),
            &mut csprng,
        )
        .await?;

        assert!(group_decrypt(
            alice_ciphertext.serialized(),
            &mut bob_store,
            &sender_address,
        )
        .await
        .is_err());

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}

#[test]
fn group_message_key_limit() -> Result<(), SignalProtocolError> {
    async {
        let mut csprng = OsRng;

        let sender_address = ProtocolAddress::new("+14159999111".to_owned(), 1.into());
        let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);

        let mut alice_store = test_in_memory_protocol_store()?;
        let mut bob_store = test_in_memory_protocol_store()?;

        let sent_distribution_message = create_sender_key_distribution_message(
            &sender_address,
            distribution_id,
            &mut alice_store,
            &mut csprng,
        )
        .await?;

        let recv_distribution_message =
            SenderKeyDistributionMessage::try_from(sent_distribution_message.serialized())?;

        process_sender_key_distribution_message(
            &sender_address,
            &recv_distribution_message,
            &mut bob_store,
        )
        .await?;

        let mut ciphertexts = Vec::with_capacity(2010);

        for _ in 0..ciphertexts.capacity() {
            ciphertexts.push(
                group_encrypt(
                    &mut alice_store,
                    &sender_address,
                    distribution_id,
                    "too many messages".as_bytes(),
                    &mut csprng,
                )
                .await?
                .serialized()
                .to_vec(),
            );
        }

        assert_eq!(
            String::from_utf8(
                group_decrypt(&ciphertexts[1000], &mut bob_store, &sender_address,).await?
            )
            .expect("valid utf8"),
            "too many messages"
        );
        assert_eq!(
            String::from_utf8(
                group_decrypt(
                    &ciphertexts[ciphertexts.len() - 1],
                    &mut bob_store,
                    &sender_address,
                )
                .await?
            )
            .expect("valid utf8"),
            "too many messages"
        );
        assert!(
            group_decrypt(&ciphertexts[0], &mut bob_store, &sender_address)
                .await
                .is_err()
        );

        Ok(())
    }
    .now_or_never()
    .expect("sync")
}
