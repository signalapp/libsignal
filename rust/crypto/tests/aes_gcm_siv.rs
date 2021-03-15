//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Deserialize, Debug)]
struct WycheproofTest {
    #[serde(rename = "tcId")]
    tc_id: usize,
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
    typ: String,
    tests: Vec<WycheproofTest>,
}

#[derive(Deserialize, Debug)]
struct WycheproofTestSet {
    algorithm: String,
    #[serde(rename = "generatorVersion")]
    generator_version: String,
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    header: Vec<String>,
    notes: HashMap<String, String>,
    schema: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofTestGroup>,
}

fn test_kat(kat: WycheproofTest) -> Result<(), signal_crypto::Error> {
    let key = hex::decode(kat.key).expect("valid hex");
    let aad = hex::decode(kat.aad).expect("valid hex");
    let nonce = hex::decode(kat.nonce).expect("valid hex");
    let tag = hex::decode(kat.tag).expect("valid hex");
    let pt = hex::decode(kat.pt).expect("valid hex");
    let ct = hex::decode(kat.ct).expect("valid hex");

    let valid = match kat.result.as_ref() {
        "valid" => true,
        "invalid" => false,
        wut => panic!("unknown result field {}", wut),
    };

    let aes_gcm_siv = signal_crypto::Aes256GcmSiv::new(&key)?;

    let mut buf = pt.clone();
    let generated_tag = aes_gcm_siv.encrypt(&mut buf, &nonce, &aad)?;

    if valid {
        assert_eq!(hex::encode(generated_tag), hex::encode(&tag));
        assert_eq!(hex::encode(&buf), hex::encode(ct));
        aes_gcm_siv.decrypt(&mut buf, &nonce, &aad, &tag)?;
        assert_eq!(hex::encode(&buf), hex::encode(pt));
    } else {
        assert_ne!(hex::encode(generated_tag), hex::encode(&tag));

        if !buf.is_empty() {
            assert_ne!(hex::encode(&buf), hex::encode(ct));
        }

        assert_eq!(
            aes_gcm_siv.decrypt(&mut buf, &nonce, &aad, &tag),
            Err(signal_crypto::Error::InvalidTag)
        );
    }

    Ok(())
}

#[test]
fn wycheproof_kats() -> Result<(), signal_crypto::Error> {
    let kat_data = include_bytes!("data/aes_gcm_siv_test.json");
    let kats: WycheproofTestSet = serde_json::from_slice(kat_data).expect("Valid JSON");

    assert_eq!(kats.algorithm, "AES-GCM-SIV");

    for group in kats.test_groups {
        if group.iv_size == 96 && group.key_size == 256 && group.tag_size == 128 {
            for test in group.tests {
                test_kat(test)?
            }
        }
    }

    Ok(())
}

#[derive(Default, Debug)]
struct BoringKat {
    key: String,
    nonce: String,
    pt: String,
    ct: String,
    aad: String,
    tag: String,
}

impl From<BoringKat> for WycheproofTest {
    fn from(bk: BoringKat) -> WycheproofTest {
        WycheproofTest {
            tc_id: 0,
            comment: "From BoringSSL".to_owned(),
            key: bk.key,
            nonce: bk.nonce,
            aad: bk.aad,
            pt: bk.pt,
            ct: bk.ct,
            tag: bk.tag,
            result: "valid".to_owned(),
            flags: vec![],
        }
    }
}

impl FromStr for BoringKat {
    type Err = ();

    fn from_str(s: &str) -> Result<BoringKat, Self::Err> {
        let mut kat: BoringKat = Default::default();
        for line in s.split('\n') {
            if line.is_empty() {
                continue;
            }
            let parts = line.split(": ").collect::<Vec<_>>();

            if parts.len() != 2 {
                panic!("Unexpected line '{}'", line);
            }

            let value = parts[1].to_string();

            match parts[0] {
                "KEY" => kat.key = value,
                "NONCE" => kat.nonce = value,
                "IN" => kat.pt = value,
                "CT" => kat.ct = value,
                "AD" => kat.aad = value,
                "TAG" => kat.tag = value,
                wut => panic!("Unknown field {}", wut),
            }
        }

        Ok(kat)
    }
}

#[test]
fn boringssl_tests() -> Result<(), signal_crypto::Error> {
    let kat_data = include_bytes!("data/boringssl.txt");
    let kat_data = String::from_utf8(kat_data.to_vec()).expect("Valid UTF-8");

    for kats in kat_data.split("\n\n") {
        let kat = BoringKat::from_str(kats).expect("valid");
        test_kat(kat.into())?;
    }

    Ok(())
}

// This test takes several minutes when compiled without optimizations.
#[cfg(not(debug_assertions))]
#[test]
fn iterated_input_test() -> Result<(), signal_crypto::Error> {
    /*
    A test which iteratively encrypts messages with lengths between 0
    and 128K bytes, with the nonce changing every invocation. Finally
    the resulting 128K ciphertext is hashed by using the AEAD with
    the entire input as the AD to compress it down to a small output.

    Output crosschecked with a program written in C calling
    BoringSSL's implementation.
    */

    let key = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .expect("valid hex");
    let aead = signal_crypto::Aes256GcmSiv::new(&key)?;

    let mut nonce = hex::decode("00112233445566778899aabb").expect("valid hex");
    let mut buf = vec![];
    let mut aad = [0u8; 32];

    for _ in 0..(128 * 1024) {
        let tag = aead.encrypt(&mut buf, &nonce, &aad)?;
        nonce[0..12].copy_from_slice(&tag[0..12]);
        buf.push(tag[15]);
        aad[(tag[13] as usize) % aad.len()] = tag[14];
    }

    let mut empty = vec![];
    let final_tag = aead.encrypt(&mut empty, &nonce, &buf)?;

    assert_eq!(hex::encode(final_tag), "329f590781135f33c9a13d9553392b06");
    Ok(())
}

// This test takes several minutes when compiled without optimizations.
#[cfg(not(debug_assertions))]
#[test]
fn long_input_tests() -> Result<(), signal_crypto::Error> {
    /*
    128 megabyte input, then hashed down to 128 bits. Crosschecked by BoringSSL
     */
    let key = hex::decode("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
        .expect("valid hex");
    let aead = signal_crypto::Aes256GcmSiv::new(&key)?;

    let nonce = hex::decode("00112233445566778899AABB").expect("valid hex");
    let mut buf = vec![0u8; 1024 * 1024 * 128];
    let aad = [0u8; 32];

    let tag = aead.encrypt(&mut buf, &nonce, &aad)?;

    assert_eq!(hex::encode(tag), "4d37433fd26590cc6e3b2217f5167cae");

    let mut empty = vec![];
    let tag = aead.encrypt(&mut empty, &nonce, &buf)?;

    assert_eq!(hex::encode(tag), "337615a813dfde73e0fe646b16780b76");
    Ok(())
}
