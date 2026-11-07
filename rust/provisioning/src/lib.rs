//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Shared client logic for provisioning a new device. The "primary" is the existing device, the "secondary" is the
//! device being provisioned.

#![warn(clippy::unwrap_used)]

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use libsignal_core::curve::{self, CurveError};
use prost::Message as _;
use rand_core::CryptoRng;
use sha2::Sha256;

mod proto;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The version byte prepended to the `ProvisionEnvelope` body
const BODY_VERSION: u8 = 0x01;

/// Errors that can occur when encrypting or receiving a `ProvisionEnvelope`
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum ProvisioningError {
    /// envelope is not a valid protobuf
    InvalidProtobuf,
    /// public key is malformed
    MalformedPubkey,
    /// envelope body is too short
    MalformedBody,
    /// invalid envelope body version: {0}
    InvalidBodyVer(u8),
    /// ephemeral public key is a low-order point
    NonContributoryKey,
    /// invalid public key version: {0}
    InvalidPubkeyVer(u8),
    /// invalid ciphertext MAC
    InvalidMac,
    /// invalid plaintext padding
    InvalidPadding,
}

/// Parses a serialized public key, i.e., the output of [`RecvProvisionCiphertextState::public_key`]
fn deserialize_public_key(pk: &[u8; 33]) -> Result<curve::PublicKey, ProvisioningError> {
    curve::PublicKey::deserialize(pk).map_err(|e| match e {
        CurveError::BadKeyType(t) => ProvisioningError::InvalidPubkeyVer(t),
        _ => ProvisioningError::MalformedPubkey,
    })
}

/// Serializes a public key into the form that [`deserialize_public_key`] accepts
fn serialize_public_key(pk: &curve::PublicKey) -> [u8; 33] {
    (*pk.serialize())
        .try_into()
        .expect("serialized X25519 public keys are 33 bytes")
}

/// Computes the X25519 shared secret between `sk` and `pk`. Also returns whether the exchange was contributory, i.e.,
/// whether the shared secret is nonzero.
fn diffie_hellman(sk: &curve::PrivateKey, pk: &curve::PublicKey) -> ([u8; 32], bool) {
    match sk.calculate_agreement(pk) {
        Ok(ss) => ((*ss).try_into().expect("shared secrets are 32B"), true),
        // The only way an X25519 agreement can fail is by producing the all-zero shared secret, so reconstruct it
        Err(_) => ([0u8; 32], false),
    }
}

/// Derives `(k_enc, k_mac)` from the X25519 shared secret
fn derive_keys(ss: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // A salt of None is equivalent to [0u8; 32] for HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(None, ss);
    let mut buf = [0u8; 64];
    hk.expand(b"TextSecure Provisioning Message", &mut buf)
        .expect("64 is a valid buffer size for HKDF-Expand");
    let chunks = buf.as_chunks::<32>().0;
    (chunks[0], chunks[1])
}

/// The state that a secondary keeps while it is waiting to receive an encrypted `ProvisionMessage` or
/// `RegistrationProvisionMessage` from the primary.
pub struct RecvProvisionCiphertextState {
    keys: curve::KeyPair,
}

impl RecvProvisionCiphertextState {
    /// Generates a new state with a fresh keypair
    pub fn generate<R: CryptoRng + ?Sized>(csprng: &mut R) -> Self {
        RecvProvisionCiphertextState {
            keys: curve::KeyPair::generate(csprng),
        }
    }

    /// The serialized public key that the primary should encrypt the `ProvisionMessage` or
    /// `RegistrationProvisionMessage` to. This is what the secondary puts in its provisioning QR code.
    pub fn public_key(&self) -> [u8; 33] {
        serialize_public_key(&self.keys.public_key)
    }

    /// Decrypts a serialized `ProvisionEnvelope` and returns the underlying serialized `ProvisionMessage` or
    /// `RegistrationProvisionMessage`. Errors if the envelope is malformed, was not encrypted to this state's public key,
    /// or has been tampered with.
    pub fn decrypt_envelope(&self, envelope: &[u8]) -> Result<Vec<u8>, ProvisioningError> {
        let envlp = proto::ProvisionEnvelope::decode(envelope)
            .map_err(|_| ProvisioningError::InvalidProtobuf)?;

        // Get the parts of the ProvisionEnvelope. In typical protobuf style, we don't distinguish between a missing
        // value and a default value. In either case, this function will error (either here or in
        // self.decrypt_envelope_inner).
        let public_key = envlp
            .public_key
            .as_deref()
            .unwrap_or_default()
            .try_into()
            .map_err(|_| ProvisioningError::MalformedPubkey)?;
        let body = envlp.body.as_deref().unwrap_or_default();

        self.decrypt_envelope_inner(public_key, body)
    }

    /// The main verification and decryption for `decrypt_envelope`
    fn decrypt_envelope_inner(
        &self,
        public_key: &[u8; 33],
        body: &[u8],
    ) -> Result<Vec<u8>, ProvisioningError> {
        // Split body into ver || iv || ct || tag
        let (ver, rest) = body
            .split_first_chunk::<1>()
            .ok_or(ProvisioningError::MalformedBody)?;
        let (iv, rest) = rest
            .split_first_chunk::<16>()
            .ok_or(ProvisioningError::MalformedBody)?;
        let (ct, tag) = rest
            .split_last_chunk::<32>()
            .ok_or(ProvisioningError::MalformedBody)?;
        if ver[0] != BODY_VERSION {
            return Err(ProvisioningError::InvalidBodyVer(ver[0]));
        }

        // Do the Diffie-Hellman on the primary's ephemeral pubkey
        let eph_pk = deserialize_public_key(public_key)?;
        let (ss, was_contributory) = diffie_hellman(&self.keys.private_key, &eph_pk);
        if !was_contributory {
            return Err(ProvisioningError::NonContributoryKey);
        }
        let (k_enc, k_mac) = derive_keys(&ss);

        // Verify the tag (in constant time) before touching the ciphertext
        let mut mac = Hmac::<Sha256>::new_from_slice(&k_mac).expect("HMAC accepts any key length");
        mac.update(ver);
        mac.update(iv);
        mac.update(ct);
        mac.verify_slice(tag)
            .map_err(|_| ProvisioningError::InvalidMac)?;

        // Decrypt the ciphertext
        let mut pt = ct.to_vec();
        // Note unpadding is not constant-time, but this is fine. We cannot have a padding oracle because we do a MAC
        // check before decrypting. This does theoretically leak the plaintext length, but we do not consider that
        // secret.
        let pt_len = Aes256CbcDec::new(&k_enc.into(), iv.into())
            .decrypt_padded::<Pkcs7>(&mut pt)
            .map_err(|_| ProvisioningError::InvalidPadding)?
            .len();
        pt.truncate(pt_len);
        Ok(pt)
    }
}

/// Encrypts the given serialized `ProvisionMessage` or `RegistrationProvisionMessage` to `secondary_pk`, returning a
/// serialized `ProvisionEnvelope`. `secondary_pk` is the output of [`RecvProvisionCiphertextState::public_key`]. Errors if
/// the first byte of `secondary_pk` is not the X25519 key type byte (0x05).
pub fn encrypt_provision_message<R: CryptoRng + ?Sized>(
    csprng: &mut R,
    secondary_pk: &[u8; 33],
    provision_message: &[u8],
) -> Result<Vec<u8>, ProvisioningError> {
    // Generate the ephemeral values
    let mut iv = [0u8; 16];
    let eph_keys = curve::KeyPair::generate(csprng);
    csprng.fill_bytes(&mut iv);

    encrypt_provision_message_deterministic(eph_keys, secondary_pk, &iv, provision_message)
}

/// The deterministic core of `encrypt_provision_message`. This is separate because it makes known-answer tests possible
fn encrypt_provision_message_deterministic(
    eph_keys: curve::KeyPair,
    secondary_pk: &[u8; 33],
    provided_iv: &[u8; 16],
    provision_message: &[u8],
) -> Result<Vec<u8>, ProvisioningError> {
    let secondary_pk = deserialize_public_key(secondary_pk)?;

    let (ss, _) = diffie_hellman(&eph_keys.private_key, &secondary_pk);
    let (k_enc, k_mac) = derive_keys(&ss);

    let ct_len = {
        let aes_block_size = 16;
        let num_ct_blocks = 1 + provision_message.len() / aes_block_size;
        num_ct_blocks * aes_block_size
    };

    // Body is ver || iv || ct || tag
    let body_len = 1 + 16 + ct_len + 32;
    let mut body = vec![0u8; body_len];
    let (ver, rest) = body.split_first_chunk_mut::<1>().expect("body_len > 1");
    let (iv, rest) = rest
        .split_first_chunk_mut::<16>()
        .expect("body_len > 1 + 16");
    let (ct, tag) = rest.split_at_mut(ct_len);

    // Write ver
    ver[0] = BODY_VERSION;
    // Write iv
    iv.copy_from_slice(provided_iv);
    // Write ct. Cannot panic because provision_message.len() < ct.len()
    ct[..provision_message.len()].copy_from_slice(provision_message);
    Aes256CbcEnc::new(&k_enc.into(), (&*iv).into())
        .encrypt_padded::<Pkcs7>(ct, provision_message.len())
        .expect("ct has room for PKCS#7 padding");
    // Write tag
    {
        let mut mac = Hmac::<Sha256>::new_from_slice(&k_mac).expect("HMAC accepts any key length");
        mac.update(ver);
        mac.update(iv);
        mac.update(ct);
        tag.copy_from_slice(mac.finalize().as_bytes());
    }

    Ok(proto::ProvisionEnvelope {
        public_key: Some(serialize_public_key(&eph_keys.public_key).to_vec()),
        body: Some(body),
    }
    .encode_to_vec())
}

#[cfg(test)]
mod tests {
    use aes::cipher::block_padding::NoPadding;
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;

    /// The key type byte that prefixes a serialized X25519 public key
    const PUBKEY_VERSION: u8 = 0x05;

    /// Known ProvisionEnvelope values, generated from Signal-Android, in JSONL format
    const KNOWN_ANSWER_TESTS: &str = r#"
{"recipient_private_key":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f","recipient_public_key":"058f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f","ephemeral_private_key":"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e7f","ephemeral_public_key":"05358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254","iv":"404142434445464748494a4b4c4d4e4f","plaintext":"hello","provision_envelope":"0a2105358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254124101404142434445464748494a4b4c4d4e4fae19d8479dfdce2c5b857cf5b341d2bd25d9da38b696b6a5cf137429541e6e1fc7add297d768b2b1a3220e5bbfb8a42d"}
{"recipient_private_key":"0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f60","recipient_public_key":"0507a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c","ephemeral_private_key":"2022232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","ephemeral_public_key":"055869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b","iv":"4142434445464748494a4b4c4d4e4f50","plaintext":"","provision_envelope":"0a21055869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b1241014142434445464748494a4b4c4d4e4f50dd38a8a5dc4f1bef76ba16640e1af03fadd0202188069af3e097e01072ed07b5758219e93cd460e0587565fa2514e798"}
{"recipient_private_key":"00030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2061","recipient_public_key":"05ab9f2628c325c141e9fb2430f106850f62930bc3f0b12df39a9b84a49c7c1d12","ephemeral_private_key":"20232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041","ephemeral_public_key":"0586c15a1119201d2a9a6023aceeaf49664a54186ad2db465845331707b6da2b0d","iv":"42434445464748494a4b4c4d4e4f5051","plaintext":"hello, world!!!","provision_envelope":"0a210586c15a1119201d2a9a6023aceeaf49664a54186ad2db465845331707b6da2b0d12410142434445464748494a4b4c4d4e4f5051e761cf0561eaccc5957d1cd34336ccbcdc3738d8c472d2d1b8f094c163d954c5838fa697e9cd42ae48df90e130c73d7d"}
{"recipient_private_key":"000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202162","recipient_public_key":"05909705b0e7d1817db56cdcb89ba2fabad3e9a01b2c23bc73e3ec9d9a2ff9b827","ephemeral_private_key":"202425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142","ephemeral_public_key":"058c487cee69b3a2e00df7707c67bbf9814f03a4756e766166ec8c82c74756bd5e","iv":"434445464748494a4b4c4d4e4f505152","plaintext":"0123456789abcdef","provision_envelope":"0a21058c487cee69b3a2e00df7707c67bbf9814f03a4756e766166ec8c82c74756bd5e125101434445464748494a4b4c4d4e4f5051520c0343cbb0229c28aa46e254574e45ba94e4794ba5c09732321d45914e4c2988867870a7c8ac0498b156a367f5e5a7f31eb7aac439e1378e2b3747dcc65babc0"}
{"recipient_private_key":"0005060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212263","recipient_public_key":"0566b76a4535f74c6f464c8f2395cb051864d00279ac88c3fc793fa00352e2ea5a","ephemeral_private_key":"2025262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243","ephemeral_public_key":"05f7161ac20bf80c387f05ca17363bfb96146d62e53b7786773b6b32b93ccf5e09","iv":"4445464748494a4b4c4d4e4f50515253","plaintext":"provisioning test vector #4 with a longer payload","provision_envelope":"0a2105f7161ac20bf80c387f05ca17363bfb96146d62e53b7786773b6b32b93ccf5e091271014445464748494a4b4c4d4e4f50515253034ee364b1954c1fcf5649e25218a8dc506d632b264d9ab85c6a97d3c7b6f806f375fd8031198869dfdcb9a561be6803063514c4e34a1d712e40b4530c76ab929aa77c04aa8e955344f68322affad658d2511d9add25e45f3b03d26107dfe3b3"}
"#;

    /// Encrypts `msg` to `recip` and parses the resulting envelope, so tests can inspect and tamper with its fields
    fn encrypt_to(recip: &RecvProvisionCiphertextState, msg: &[u8]) -> proto::ProvisionEnvelope {
        let envlp = encrypt_provision_message(&mut rand::rng(), &recip.public_key(), msg)
            .expect("valid public key");
        proto::ProvisionEnvelope::decode(&*envlp).expect("valid protobuf")
    }

    /// Serializes an envelope with the given fields and decrypts it
    fn decrypt_with_fields(
        recip: &RecvProvisionCiphertextState,
        public_key: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>, ProvisioningError> {
        let envlp = proto::ProvisionEnvelope {
            public_key: Some(public_key.to_vec()),
            body: Some(body.to_vec()),
        };
        recip.decrypt_envelope(&envlp.encode_to_vec())
    }

    /// Checks correctness of `ProvisionMessage`/`RegistrationProvisionMessage` encryption
    #[test_case(0; "empty")]
    #[test_case(1; "one byte")]
    #[test_case(15; "one less than block")]
    #[test_case(16; "exactly one block")]
    #[test_case(17; "one more than block")]
    #[test_case(1000; "many blocks")]
    fn round_trip(len: usize) {
        let recipient = RecvProvisionCiphertextState::generate(&mut rand::rng());
        let msg: Vec<u8> = (0..=u8::MAX).cycle().take(len).collect();

        let envlp = encrypt_provision_message(&mut rand::rng(), &recipient.public_key(), &msg)
            .expect("valid public key");
        let decrypted = recipient.decrypt_envelope(&envlp).expect("valid envelope");
        assert_eq!(decrypted, msg);

        let envlp = proto::ProvisionEnvelope::decode(&*envlp).expect("valid protobuf");
        assert_eq!(envlp.public_key().len(), 33);
        assert_eq!(envlp.public_key()[0], PUBKEY_VERSION);
        assert_eq!(envlp.body()[0], BODY_VERSION);
        // PKCS#7 padding always adds between 1 and 16 bytes of padding
        let ct_len = (len / 16 + 1) * 16;
        assert_eq!(envlp.body().len(), 1 + 16 + ct_len + 32);
    }

    /// Checks that encrypting to a public key with the wrong version byte fails
    #[test]
    fn encrypt_bad_public_key_version() {
        let recipient = RecvProvisionCiphertextState::generate(&mut rand::rng());
        assert_eq!(recipient.public_key()[0], PUBKEY_VERSION);

        let mut public_key = recipient.public_key();
        public_key[0] = 0x06;
        assert_matches!(
            encrypt_provision_message(&mut rand::rng(), &public_key, b"hello"),
            Err(ProvisioningError::InvalidPubkeyVer(0x06))
        );
    }

    /// Checks that malformed serialized envelopes are rejected
    #[test]
    fn malformed_serialized() {
        let recipient = RecvProvisionCiphertextState::generate(&mut rand::rng());
        let envlp = encrypt_to(&recipient, b"hello");

        assert_matches!(
            recipient.decrypt_envelope(&[0xff]),
            Err(ProvisioningError::InvalidProtobuf)
        );

        let missing_key = proto::ProvisionEnvelope {
            public_key: None,
            ..envlp.clone()
        };
        assert_matches!(
            recipient.decrypt_envelope(&missing_key.encode_to_vec()),
            Err(ProvisioningError::MalformedPubkey)
        );

        assert_matches!(
            decrypt_with_fields(&recipient, &envlp.public_key()[1..], envlp.body()),
            Err(ProvisioningError::MalformedPubkey)
        );

        // A present-but-empty field is encoded differently from an absent one, and must also be rejected
        let empty_key = proto::ProvisionEnvelope {
            public_key: Some(vec![]),
            ..envlp.clone()
        };
        assert_ne!(empty_key.encode_to_vec(), missing_key.encode_to_vec());
        assert_matches!(
            recipient.decrypt_envelope(&empty_key.encode_to_vec()),
            Err(ProvisioningError::MalformedPubkey)
        );

        let missing_body = proto::ProvisionEnvelope {
            body: None,
            ..envlp.clone()
        };
        assert_matches!(
            recipient.decrypt_envelope(&missing_body.encode_to_vec()),
            Err(ProvisioningError::MalformedBody)
        );

        let empty_body = proto::ProvisionEnvelope {
            body: Some(vec![]),
            ..envlp
        };
        assert_ne!(empty_body.encode_to_vec(), missing_body.encode_to_vec());
        assert_matches!(
            recipient.decrypt_envelope(&empty_body.encode_to_vec()),
            Err(ProvisioningError::MalformedBody)
        );
    }

    /// Checks that tampering with the `ProvisionEnvelope` body anywhere yields an error
    #[test]
    fn tampered_body() {
        let recipient = RecvProvisionCiphertextState::generate(&mut rand::rng());
        let envlp = encrypt_to(&recipient, b"a message that spans more than one block");

        for i in 0..envlp.body().len() {
            let mut body = envlp.body().to_vec();
            body[i] ^= 0x01;
            let result = decrypt_with_fields(&recipient, envlp.public_key(), &body);
            if i == 0 {
                assert_matches!(result, Err(ProvisioningError::InvalidBodyVer(0x00)));
            } else {
                assert_matches!(result, Err(ProvisioningError::InvalidMac), "byte {i}");
            }
        }
    }

    /// Checks that tampering with the public key version or contents yields an error
    #[test]
    fn tampered_public_key() {
        let recipient = RecvProvisionCiphertextState::generate(&mut rand::rng());
        let envlp = encrypt_to(&recipient, b"hello");

        let mut public_key = envlp.public_key().to_vec();
        public_key[0] = 0x06;
        assert_matches!(
            decrypt_with_fields(&recipient, &public_key, envlp.body()),
            Err(ProvisioningError::InvalidPubkeyVer(0x06))
        );

        let mut public_key = envlp.public_key().to_vec();
        public_key[1] ^= 0x01;
        assert_matches!(
            decrypt_with_fields(&recipient, &public_key, envlp.body()),
            Err(ProvisioningError::InvalidMac)
        );

        // Check that receiving with a totally different keypair also fails
        let other = RecvProvisionCiphertextState::generate(&mut rand::rng());
        let envlp = encrypt_provision_message(&mut rand::rng(), &recipient.public_key(), b"hello")
            .expect("valid public key");
        assert_matches!(
            other.decrypt_envelope(&envlp),
            Err(ProvisioningError::InvalidMac)
        );
    }

    /// Checks that non-contributory `ProvisionEnvelope`s are rejected
    #[test]
    fn low_order_public_key() {
        let recipient = RecvProvisionCiphertextState::generate(&mut rand::rng());
        let envlp = encrypt_to(&recipient, b"hello");

        let mut public_key = [0u8; 33];
        public_key[0] = PUBKEY_VERSION;
        assert_matches!(
            decrypt_with_fields(&recipient, &public_key, envlp.body()),
            Err(ProvisioningError::NonContributoryKey)
        );
    }

    /// Checks that plaintexts with invalid PKCS#7 padding are rejected
    #[test]
    fn valid_mac_bad_padding() {
        let recipient = RecvProvisionCiphertextState::generate(&mut rand::rng());

        // Build an envelope by hand whose plaintext block ends in 0x00, which is never valid PKCS7
        let eph_keys = curve::KeyPair::generate(&mut rand::rng());
        let recipient_pk =
            deserialize_public_key(&recipient.public_key()).expect("valid public key");
        let (ss, _) = diffie_hellman(&eph_keys.private_key, &recipient_pk);
        let (k_enc, k_mac) = derive_keys(&ss);

        let iv = [0x24u8; 16];
        let mut ct = [0u8; 16];
        Aes256CbcEnc::new(&k_enc.into(), (&iv).into())
            .encrypt_padded::<NoPadding>(&mut ct, 16)
            .expect("block-aligned");

        let mut mac = Hmac::<Sha256>::new_from_slice(&k_mac).expect("any key length");
        mac.update(&[0x01]);
        mac.update(&iv);
        mac.update(&ct);
        let tag = mac.finalize().into_bytes();

        let body = [&[0x01][..], &iv, &ct, &tag].concat();
        let public_key = serialize_public_key(&eph_keys.public_key);

        assert_matches!(
            decrypt_with_fields(&recipient, &public_key, &body),
            Err(ProvisioningError::InvalidPadding)
        );
    }

    /// One line of [`KNOWN_ANSWER_TESTS`]. All fields but `plaintext` are hex-encoded.
    #[derive(serde::Deserialize)]
    struct TestVector {
        recipient_private_key: String,
        recipient_public_key: String,
        ephemeral_private_key: String,
        ephemeral_public_key: String,
        iv: String,
        plaintext: String,
        provision_envelope: String,
    }

    /// Constructs a keypair from a hex-encoded private key, and checks that it matches the hex-encoded public key
    fn keypair_from_hex(private_key: &str, public_key: &str) -> curve::KeyPair {
        let sk = curve::PrivateKey::deserialize(&hex::decode(private_key).expect("valid hex"))
            .expect("valid private key");
        let keys = curve::KeyPair::try_from(sk).expect("valid private key");
        assert_eq!(hex::encode(keys.public_key.serialize()), public_key);
        keys
    }

    /// Checks that encryption and decryption match the envelopes in [`KNOWN_ANSWER_TESTS`]
    #[test]
    fn known_answers() {
        let tests = KNOWN_ANSWER_TESTS.lines().filter(|line| !line.is_empty());
        let mut num_tests = 0;
        for (i, line) in tests.enumerate() {
            let tv: TestVector = serde_json::from_str(line).expect("valid test vector");

            let recipient = RecvProvisionCiphertextState {
                keys: keypair_from_hex(&tv.recipient_private_key, &tv.recipient_public_key),
            };
            let eph_keys = keypair_from_hex(&tv.ephemeral_private_key, &tv.ephemeral_public_key);
            let iv = hex::decode(&tv.iv)
                .expect("valid hex")
                .try_into()
                .expect("16-byte IV");
            let expected_envelope = hex::decode(&tv.provision_envelope).expect("valid hex");

            // Check the computed envelope matches the expected one
            let computed_envelope = encrypt_provision_message_deterministic(
                eph_keys,
                &recipient.public_key(),
                &iv,
                tv.plaintext.as_bytes(),
            )
            .expect("valid public key");
            assert_eq!(computed_envelope, expected_envelope, "vector {i}");

            // Check that decryption produces the same plaintext
            let decrypted = recipient
                .decrypt_envelope(&expected_envelope)
                .expect("valid envelope");
            assert_eq!(decrypted, tv.plaintext.as_bytes(), "vector {i}");

            num_tests += 1;
        }

        // Check the test vectors were actually parsed
        assert_eq!(num_tests, 5);
    }
}
