//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;

use const_str::hex;
use rand::{Rng, TryRngCore as _};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct WycheproofTest {
    #[serde(rename = "tcId")]
    #[expect(dead_code)]
    tc_id: usize,
    #[expect(dead_code)]
    comment: String,
    key: String,
    #[serde(rename = "iv")]
    nonce: String,
    aad: String,
    #[serde(rename = "msg")]
    pt: String,
    ct: String,
    tag: String,
    result: String,
    #[expect(dead_code)]
    flags: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct WycheproofTestGroup {
    #[serde(rename = "ivSize")]
    iv_size: usize,
    #[serde(rename = "keySize")]
    key_size: usize,
    #[serde(rename = "tagSize")]
    tag_size: usize,
    #[serde(rename = "type")]
    #[expect(dead_code)]
    typ: String,
    tests: Vec<WycheproofTest>,
}

#[derive(Deserialize, Debug)]
struct WycheproofTestSet {
    algorithm: String,
    #[serde(rename = "generatorVersion")]
    #[expect(dead_code)]
    generator_version: String,
    #[serde(rename = "numberOfTests")]
    #[expect(dead_code)]
    number_of_tests: usize,
    #[expect(dead_code)]
    header: Vec<String>,
    #[expect(dead_code)]
    notes: HashMap<String, String>,
    #[expect(dead_code)]
    schema: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofTestGroup>,
}

fn test_kat(kat: WycheproofTest) -> Result<(), signal_crypto::Error> {
    let mut rng = rand::rngs::OsRng.unwrap_err();

    let key = hex::decode(kat.key).expect("valid hex");
    let aad = hex::decode(kat.aad).expect("valid hex");
    let nonce = hex::decode(kat.nonce).expect("valid hex");
    let tag = hex::decode(kat.tag).expect("valid hex");
    let pt = hex::decode(kat.pt).expect("valid hex");
    let ct = hex::decode(kat.ct).expect("valid hex");

    let valid = match kat.result.as_ref() {
        "valid" => true,
        "invalid" => false,
        wut => panic!("unknown result field {wut}"),
    };

    let mut gcm_enc = signal_crypto::Aes256GcmEncryption::new(&key, &nonce, &aad)?;

    let mut buf = pt.clone();
    gcm_enc.encrypt(&mut buf);
    let generated_tag = gcm_enc.compute_tag();

    let mut gcm_dec = signal_crypto::Aes256GcmDecryption::new(&key, &nonce, &aad)?;

    if valid {
        assert_eq!(hex::encode(generated_tag), hex::encode(&tag));
        assert_eq!(hex::encode(&buf), hex::encode(&ct));

        gcm_dec.decrypt(&mut buf);
        assert!(gcm_dec.verify_tag(&tag).is_ok());
        assert_eq!(hex::encode(&buf), hex::encode(&pt));

        for i in 2..32 {
            println!("Test {i}");
            // Do it again but with split inputs:
            let mut gcm_enc = signal_crypto::Aes256GcmEncryption::new(&key, &nonce, &aad)?;
            let mut gcm_dec = signal_crypto::Aes256GcmDecryption::new(&key, &nonce, &aad)?;

            let mut enc_buf = pt.clone();
            let mut dec_buf = ct.clone();

            let mut processed = 0;
            while processed != buf.len() {
                let remaining = buf.len() - processed;
                let this_time = if remaining > 1 {
                    rng.random_range(1..remaining)
                } else {
                    remaining
                };
                assert!(this_time > 0);
                gcm_enc.encrypt(&mut enc_buf[processed..processed + this_time]);
                gcm_dec.decrypt(&mut dec_buf[processed..processed + this_time]);
                processed += this_time;
            }

            assert_eq!(hex::encode(gcm_enc.compute_tag()), hex::encode(&tag));
            assert!(gcm_dec.verify_tag(&tag).is_ok());

            assert_eq!(hex::encode(enc_buf), hex::encode(&ct));
            assert_eq!(hex::encode(dec_buf), hex::encode(&pt));
        }
    } else {
        assert_ne!(hex::encode(generated_tag), hex::encode(&tag));

        gcm_dec.decrypt(&mut buf);

        assert!(matches!(
            gcm_dec.verify_tag(&tag),
            Err(signal_crypto::Error::InvalidTag)
        ));
    }

    Ok(())
}

#[test]
fn aes_gcm_wycheproof_kats() -> Result<(), signal_crypto::Error> {
    let kat_data = include_bytes!("data/aes_gcm_test.json");
    let kats: WycheproofTestSet = serde_json::from_slice(kat_data).expect("Valid JSON");

    assert_eq!(kats.algorithm, "AES-GCM");

    for group in kats.test_groups {
        if group.iv_size == 96 && group.key_size == 256 && group.tag_size == 128 {
            for test in group.tests {
                test_kat(test)?
            }
        }
    }

    Ok(())
}

#[test]
fn aes_gcm_smoke_test() -> Result<(), signal_crypto::Error> {
    let key = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = hex!("cafebabefacedbaddecaf888");
    let input = hex!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    );
    let ad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let output = hex!(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"
    );

    let mut aes_gcm = signal_crypto::Aes256GcmEncryption::new(&key, &nonce, &ad)?;

    let mut buf = input.to_vec();
    aes_gcm.encrypt(&mut buf);
    let tag = aes_gcm.compute_tag();

    buf.extend_from_slice(&tag);
    assert_eq!(hex::encode(buf), hex::encode(output));

    Ok(())
}
