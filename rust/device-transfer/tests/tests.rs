//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use device_transfer::*;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::x509::X509;

#[test]
fn test_generate_and_parse() -> Result<(), Error> {
    let bit_size = 4096;
    let key = create_rsa_private_key(bit_size)?;
    let cert = create_self_signed_cert(&key, "test", 10)?;

    println!("key = {}", hex::encode(&key));
    println!("cert = {}", hex::encode(&cert));

    let openssl_key = PKey::private_key_from_der(&key).expect("OpenSSL can parse our PKCS8 key");
    // Try to use the key

    let openssl_rsa = openssl_key.rsa().expect("This is a RSA key");

    let mut signature = vec![0; bit_size / 8];
    let digest = vec![0x23; 20];
    let sig_len = openssl_rsa
        .private_encrypt(&digest, &mut signature, Padding::PKCS1)
        .unwrap();
    assert_eq!(sig_len, bit_size / 8);

    assert!(openssl_rsa.check_key().unwrap());

    let openssl_cert = X509::from_der(&cert).expect("OpenSSL can parse our certificate");
    let pubkey = openssl_cert.public_key().expect("Can extract public key");

    // Self-signature verifies:
    assert!(openssl_cert.verify(&pubkey).unwrap());

    Ok(())
}
