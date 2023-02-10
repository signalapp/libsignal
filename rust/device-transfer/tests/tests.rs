//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::Ordering;
use std::convert::TryInto;
use std::time::{Duration, SystemTime};

use boring::asn1::Asn1Time;
use boring::pkey::PKey;
use boring::rsa::Padding;
use boring::x509::X509;

use device_transfer::*;

#[test]
fn test_generate_and_parse() -> Result<(), Error> {
    for key_format in [KeyFormat::KeySpecific, KeyFormat::Pkcs8] {
        let bit_size = 4096;
        let key = create_rsa_private_key(bit_size, key_format)?;
        let days_to_expire = 10;
        let cert = create_self_signed_cert(&key, "test", days_to_expire)?;

        println!("Key format: {:?}", key_format);
        println!("key = {}", hex::encode(&key));
        println!("cert = {}", hex::encode(&cert));

        let boring_key =
            PKey::private_key_from_der(&key).expect("BoringSSL can parse our private key");
        // Try to use the key

        let boring_rsa = boring_key.rsa().expect("This is a RSA key");

        let mut signature = vec![0; bit_size / 8];
        let digest = vec![0x23; 20];
        let sig_len = boring_rsa
            .private_encrypt(&digest, &mut signature, Padding::PKCS1)
            .unwrap();
        assert_eq!(sig_len, bit_size / 8);

        assert!(boring_rsa.check_key().unwrap());

        let boring_cert = X509::from_der(&cert).expect("BoringSSL can parse our certificate");
        let pubkey = boring_cert.public_key().expect("Can extract public key");

        // Self-signature verifies:
        assert!(boring_cert.verify(&pubkey).unwrap());

        // Cert should be valid an hour ago, to allow for clock skew
        let one_hour_ago: libc::time_t = (SystemTime::now() - Duration::from_secs(60 * 60))
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Valid duration")
            .as_secs()
            .try_into()
            .expect("Duration seconds should fit in i64");
        let one_hour_ago = Asn1Time::from_unix(one_hour_ago).expect("Valid timestamp");

        let start = boring_cert.not_before();
        let start_ordering = start
            .compare(&one_hour_ago)
            .expect("comparison should not fail");
        assert_eq!(Ordering::Less, start_ordering);

        let after_expiration =
            Asn1Time::days_from_now(days_to_expire + 1).expect("Should not fail");
        let expires = boring_cert.not_after();
        let expires_ordering = expires
            .compare(&after_expiration)
            .expect("comparison should not fail");
        assert_eq!(Ordering::Less, expires_ordering);
    }

    Ok(())
}
