//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_rust::*;
use rand::rngs::OsRng;

#[test]
fn test_server_cert() -> Result<(), SignalProtocolError> {
    let mut rng = OsRng;
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert = ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

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
            },
            Err(e) => {
                match e {
                    SignalProtocolError::InvalidProtobufEncoding |
                    SignalProtocolError::ProtobufDecodingError(_) |
                    SignalProtocolError::BadKeyType(_) => {},

                    unexpected_err => {
                        panic!("unexpected error {:?}", unexpected_err)
                    }
                }
            }
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

    let server_cert = ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let device_id = 42;
    let expires = 1605722925;

    let sender_cert = SenderCertificate::new(Some("9d0652a3-dcc3-4d11-975f-74d61598733f".to_string()),
                                             Some("+14152222222".to_string()),
                                             key.public_key,
                                             device_id,
                                             expires,
                                             server_cert,
                                             &server_key.private_key,
                                             &mut rng)?;

    assert_eq!(sender_cert.validate(&trust_root.public_key, expires), Ok(true));
    assert_eq!(sender_cert.validate(&trust_root.public_key, expires + 1), Ok(false)); // expired

    let mut sender_cert_data = sender_cert.serialized()?.to_vec();
    let sender_cert_bits = sender_cert_data.len() * 8;

    for b in 0..sender_cert_bits {
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip a bit
        let cert = SenderCertificate::deserialize(&sender_cert_data);
        sender_cert_data[b / 8] ^= 1u8 << (b % 8); // flip the bit back

        match cert {
            Ok(cert) => {
                assert_eq!(cert.validate(&trust_root.public_key, expires), Ok(false));
            },
            Err(e) => {
                match e {
                    SignalProtocolError::InvalidProtobufEncoding |
                    SignalProtocolError::ProtobufDecodingError(_) |
                    SignalProtocolError::BadKeyType(_) => {
                    },

                    unexpected_err => {
                        panic!("unexpected error {:?}", unexpected_err)
                    }
                }
            }
        }
    }

    Ok(())
}
