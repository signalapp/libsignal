//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::Mac;
use prost::Message;
use rand::{CryptoRng, Rng};
use signal_crypto::{aes_256_cbc_decrypt, aes_256_cbc_encrypt};
use subtle::ConstantTimeEq;

use crate::constants::{
    USERNAME_LINK_ENTROPY_SIZE, USERNAME_LINK_HMAC_LEN, USERNAME_LINK_IV_SIZE,
    USERNAME_LINK_KEY_SIZE, USERNAME_LINK_LABEL_AUTHENTICATION_KEY,
    USERNAME_LINK_LABEL_ENCRYPTION_KEY,
};
use crate::{proto, UsernameLinkError};

/// Generates the encrypted buffer used for a username link, decryptable by [`decrypt_username`].
///
/// The encryption key will be derived from `entropy` is provided, and generated from `rng` if not.
/// (An ephemeral IV will be generated from `rng` regardless.) The entropy used will be returned
/// along with the encrypted buffer.
pub fn create_for_username<R: Rng + CryptoRng>(
    rng: &mut R,
    username: String,
    entropy: Option<&[u8; USERNAME_LINK_ENTROPY_SIZE]>,
) -> Result<([u8; USERNAME_LINK_ENTROPY_SIZE], Vec<u8>), UsernameLinkError> {
    const AES_BLOCK_SIZE: usize = 16;
    let padding = vec![0; (AES_BLOCK_SIZE * 3).saturating_sub(username.len())];

    let username_data = proto::username::UsernameData { username, padding };
    let ptext = username_data.encode_to_vec();
    debug_assert!(
        ptext.len() > AES_BLOCK_SIZE * 3,
        "padded to fill four AES blocks (with room for PKCS#7 padding in the last block"
    );
    if ptext.len() >= AES_BLOCK_SIZE * 4 {
        return Err(UsernameLinkError::InputDataTooLong);
    }
    let entropy: [u8; USERNAME_LINK_ENTROPY_SIZE] =
        entropy.copied().unwrap_or_else(|| random_bytes(rng));
    let iv: [u8; USERNAME_LINK_IV_SIZE] = random_bytes(rng);
    let aes_key = hkdf(&entropy, USERNAME_LINK_LABEL_ENCRYPTION_KEY);
    let mac_key = hkdf(&entropy, USERNAME_LINK_LABEL_AUTHENTICATION_KEY);
    let ctext = aes_256_cbc_encrypt(&ptext, &aes_key, &iv).expect("valid key and iv");

    let mut buf: Vec<u8> =
        Vec::with_capacity(USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN + ctext.len());
    buf.extend(iv.as_slice());
    buf.extend(ctext);
    buf.extend(hmac(&mac_key, buf.as_slice()));
    Ok((entropy, buf))
}

pub fn decrypt_username(
    entropy: &[u8; USERNAME_LINK_ENTROPY_SIZE],
    encrypted_username: &[u8],
) -> Result<String, UsernameLinkError> {
    let len = encrypted_username.len();
    if len <= USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN {
        return Err(UsernameLinkError::UsernameLinkDataTooShort);
    }

    let mac_key = hkdf(entropy, USERNAME_LINK_LABEL_AUTHENTICATION_KEY);
    let (iv_and_ctext, expected_hash) = encrypted_username.split_at(len - USERNAME_LINK_HMAC_LEN);
    let actual_hash = hmac(&mac_key, iv_and_ctext);

    if !bool::from(expected_hash.ct_eq(&actual_hash)) {
        return Err(UsernameLinkError::HmacMismatch);
    }

    let ctext = &encrypted_username[USERNAME_LINK_IV_SIZE..len - USERNAME_LINK_HMAC_LEN];
    let aes_key = hkdf(entropy, USERNAME_LINK_LABEL_ENCRYPTION_KEY);
    let iv = &encrypted_username[..USERNAME_LINK_IV_SIZE];
    let ptext =
        aes_256_cbc_decrypt(ctext, &aes_key, iv).map_err(|_| UsernameLinkError::BadCiphertext)?;

    let username_data = proto::username::UsernameData::decode(ptext.as_slice())
        .map_err(|_| UsernameLinkError::InvalidDecryptedDataStructure)?;
    Ok(username_data.username)
}

fn hkdf(entropy: &[u8], label: &[u8]) -> [u8; USERNAME_LINK_KEY_SIZE] {
    let mut result = [0u8; USERNAME_LINK_KEY_SIZE];
    hkdf::Hkdf::<sha2::Sha256>::new(None, entropy)
        .expand(label, &mut result)
        .expect("valid length");
    result
}

fn hmac(mac_key: &[u8], input: &[u8]) -> Vec<u8> {
    hmac::Hmac::<sha2::Sha256>::new_from_slice(mac_key)
        .expect("HMAC accepts any key length")
        .chain_update(input)
        .finalize()
        .into_bytes()
        .to_vec()
}

fn random_bytes<const SIZE: usize, R: Rng + CryptoRng>(rng: &mut R) -> [u8; SIZE] {
    let mut result = [0u8; SIZE];
    rng.fill_bytes(&mut result);
    result
}

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;

    use super::*;
    use crate::constants::{DISCRIMINATOR_RANGES, MAX_NICKNAME_LENGTH};

    const TEST_CTEXT_SIZE: usize = 32;

    #[test]
    fn input_data_too_long() {
        let mut csprng = OsRng;
        let long_username = "\
            abcdefghijklmnopqrstuvwxyz\
            abcdefghijklmnopqrstuvwxyz\
            abcdefghijklmnopqrstuvwxyz\
            abcdefghijklmnopqrstuvwxyz\
            abcdefghijklmnopqrstuvwxyz";
        assert!(matches!(
            create_for_username(&mut csprng, long_username.to_string(), None),
            Err(UsernameLinkError::InputDataTooLong)
        ));
    }

    #[test]
    fn username_link_data_too_short() {
        let entropy = [0u8; USERNAME_LINK_ENTROPY_SIZE];
        let encrypted_username = [0u8; USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN];
        assert!(matches!(
            decrypt_username(&entropy, &encrypted_username),
            Err(UsernameLinkError::UsernameLinkDataTooShort)
        ));
    }

    #[test]
    fn username_link_data_hmac_no_match() {
        let entropy = [0u8; USERNAME_LINK_ENTROPY_SIZE];
        let encrypted_username =
            [0u8; USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN + TEST_CTEXT_SIZE];
        assert!(matches!(
            decrypt_username(&entropy, &encrypted_username),
            Err(UsernameLinkError::HmacMismatch)
        ));
    }

    #[test]
    fn username_link_data_bad_ciphertext() {
        let entropy = [0u8; USERNAME_LINK_ENTROPY_SIZE];
        let mut encrypted_username =
            [0u8; USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN + TEST_CTEXT_SIZE];
        let mac_key = hkdf(&entropy, USERNAME_LINK_LABEL_AUTHENTICATION_KEY);
        let hmac = hmac(
            &mac_key,
            &encrypted_username[..USERNAME_LINK_IV_SIZE + TEST_CTEXT_SIZE],
        );
        encrypted_username[USERNAME_LINK_IV_SIZE + TEST_CTEXT_SIZE..].clone_from_slice(&hmac);
        assert!(matches!(
            decrypt_username(&entropy, &encrypted_username),
            Err(UsernameLinkError::BadCiphertext)
        ));
    }

    #[test]
    fn username_link_decrypted_data_bad_structure() {
        let entropy = [0u8; USERNAME_LINK_ENTROPY_SIZE];
        let mac_key = hkdf(&entropy, USERNAME_LINK_LABEL_AUTHENTICATION_KEY);
        let aes_key = hkdf(&entropy, USERNAME_LINK_LABEL_ENCRYPTION_KEY);
        let mut encrypted_username =
            [0u8; USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN + TEST_CTEXT_SIZE];

        let ptext = [0u8; TEST_CTEXT_SIZE - 1];
        let ctext = aes_256_cbc_encrypt(
            &ptext,
            &aes_key,
            &encrypted_username[..USERNAME_LINK_IV_SIZE],
        )
        .expect("valid iv and key");
        encrypted_username[USERNAME_LINK_IV_SIZE..USERNAME_LINK_IV_SIZE + TEST_CTEXT_SIZE]
            .clone_from_slice(&ctext);

        let hmac = hmac(
            &mac_key,
            &encrypted_username[..USERNAME_LINK_IV_SIZE + TEST_CTEXT_SIZE],
        );
        encrypted_username[USERNAME_LINK_IV_SIZE + TEST_CTEXT_SIZE..].clone_from_slice(&hmac);
        assert!(matches!(
            decrypt_username(&entropy, &encrypted_username),
            Err(UsernameLinkError::InvalidDecryptedDataStructure)
        ));
    }

    #[test]
    fn happy_case() {
        let expected_username = "test_username.42";
        let mut csprng = OsRng;
        let (entropy, encrypted_username) =
            create_for_username(&mut csprng, expected_username.into(), None).expect("no error");
        let actual_username = decrypt_username(&entropy, &encrypted_username).expect("no error");
        assert_eq!(expected_username, actual_username);
    }

    #[test]
    fn longest_valid_username() {
        let expected_username = format!(
            "{}.{}",
            ["a"; MAX_NICKNAME_LENGTH].join(""),
            DISCRIMINATOR_RANGES.last().expect("non-empty").end - 1
        );
        let mut csprng = OsRng;
        let (entropy, encrypted_username) =
            create_for_username(&mut csprng, expected_username.clone(), None).expect("no error");
        let actual_username = decrypt_username(&entropy, &encrypted_username).expect("no error");
        assert_eq!(expected_username, actual_username);
    }

    #[test]
    fn reuse_entropy() {
        let expected_username = "test_username.42";
        let mut csprng = OsRng;
        let (entropy, encrypted_username) =
            create_for_username(&mut csprng, expected_username.into(), None).expect("no error");
        let actual_username = decrypt_username(&entropy, &encrypted_username).expect("no error");
        assert_eq!(expected_username, actual_username);

        let (new_entropy, new_encrypted_username) =
            create_for_username(&mut csprng, expected_username.into(), Some(&entropy))
                .expect("no error");
        assert_eq!(entropy, new_entropy);
        assert_ne!(encrypted_username, new_encrypted_username);
        let actual_username =
            decrypt_username(&entropy, &new_encrypted_username).expect("no error");
        assert_eq!(expected_username, actual_username);
    }

    #[test]
    fn prost_ignores_unknown_fields_and_handles_missing_ones() {
        // Field # 0b1111111_1111 (way higher than anything we'd use) with a type of VARINT (0) and a value of 0
        // See https://protobuf.dev/programming-guides/encoding/
        #[allow(clippy::unusual_byte_groupings)]
        let not_an_encoded_username_proto = [0b1_1111_000, 0b0_1111111, 0];
        let username_message =
            proto::username::UsernameData::decode(not_an_encoded_username_proto.as_slice())
                .expect("valid if vacuous");
        assert_eq!("", &username_message.username);
    }
}
