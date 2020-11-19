//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod support;

use futures::executor::block_on;
use libsignal_protocol_rust::*;
use rand::rngs::OsRng;
use support::*;

#[test]
fn test_server_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let serialized = server_cert.serialized()?.to_vec();

    let recovered = ServerCertificate::deserialize(&serialized)?;

    assert_eq!(recovered.validate(&trust_root.public_key), Ok(true));

    let mut cert_data = serialized.clone();
    let cert_bits = cert_data.len() * 8;

    for b in 0..cert_bits {
        cert_data[b / 8] ^= 1u8 << (b % 8); // flip a bit
        let cert = ServerCertificate::deserialize(&cert_data);
        cert_data[b / 8] ^= 1u8 << (b % 8); // flip the bit back

        match cert {
            Ok(cert) => {
                assert_eq!(cert.validate(&trust_root.public_key), Ok(false));
            }
            Err(e) => match e {
                SignalProtocolError::InvalidProtobufEncoding
                | SignalProtocolError::ProtobufDecodingError(_)
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
fn test_sender_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);
    let key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let device_id = 42;
    let expires = 1605722925;

    let sender_cert = SenderCertificate::new(
        Some("9d0652a3-dcc3-4d11-975f-74d61598733f".to_string()),
        Some("+14152222222".to_string()),
        key.public_key,
        device_id,
        expires,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )?;

    assert_eq!(
        sender_cert.validate(&trust_root.public_key, expires),
        Ok(true)
    );
    assert_eq!(
        sender_cert.validate(&trust_root.public_key, expires + 1),
        Ok(false)
    ); // expired

    let mut sender_cert_data = sender_cert.serialized()?.to_vec();
    let sender_cert_bits = sender_cert_data.len() * 8;

    for b in 0..sender_cert_bits {
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip a bit
        let cert = SenderCertificate::deserialize(&sender_cert_data);
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip the bit back

        match cert {
            Ok(cert) => {
                assert_eq!(cert.validate(&trust_root.public_key, expires), Ok(false));
            }
            Err(e) => match e {
                SignalProtocolError::InvalidProtobufEncoding
                | SignalProtocolError::ProtobufDecodingError(_)
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
    block_on(async {
        let mut rng = OsRng;

        let alice_device_id = 23;
        let bob_device_id = 42;

        let alice_e164 = "+14151111111".to_owned();
        let bob_e164 = "+14151114444".to_owned();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

        let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

        let mut alice_store = support::test_in_memory_protocol_store();
        let mut bob_store = support::test_in_memory_protocol_store();

        let alice_pubkey = *alice_store.get_identity_key_pair(None).await?.public_key();

        let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

        process_prekey_bundle(
            &bob_uuid_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_pre_key_bundle,
            &mut rng,
            None,
        )
        .await?;

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);

        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

        let expires = 1605722925;

        let sender_cert = SenderCertificate::new(
            Some(alice_uuid.clone()),
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
            None,
            &mut rng,
        )
        .await?;

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &trust_root.public_key,
            expires - 1,
            Some(bob_e164.clone()),
            Some(bob_uuid.clone()),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
        )
        .await?;

        assert_eq!(bob_ptext.message, alice_ptext);
        assert_eq!(bob_ptext.sender_uuid, Some(alice_uuid));
        assert_eq!(bob_ptext.sender_e164, Some(alice_e164));
        assert_eq!(bob_ptext.device_id, alice_device_id);

        // Now test but with an expired cert:

        let alice_ctext = sealed_sender_encrypt(
            &bob_uuid_address,
            &sender_cert,
            &alice_ptext,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            None,
            &mut rng,
        )
        .await?;

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &trust_root.public_key,
            expires + 11,
            Some(bob_e164.clone()),
            Some(bob_uuid.clone()),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
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
            None,
            &mut rng,
        )
        .await?;

        let wrong_trust_root = KeyPair::generate(&mut rng);

        let bob_ptext = sealed_sender_decrypt(
            &alice_ctext,
            &wrong_trust_root.public_key,
            expires - 1,
            Some(bob_e164.clone()),
            Some(bob_uuid.clone()),
            bob_device_id,
            &mut bob_store.identity_store,
            &mut bob_store.session_store,
            &mut bob_store.pre_key_store,
            &mut bob_store.signed_pre_key_store,
            None,
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
    })
}
