//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::subtle::ConstantTimeEq;
use prost::Message;
use rand::{CryptoRng, Rng};

use signal_crypto::{aes_256_cbc_decrypt, aes_256_cbc_encrypt, CryptographicMac};

use crate::constants::{
    USERNAME_LINK_ENTROPY_SIZE, USERNAME_LINK_HMAC_ALGORITHM, USERNAME_LINK_HMAC_LEN,
    USERNAME_LINK_IV_SIZE, USERNAME_LINK_KEY_SIZE, USERNAME_LINK_LABEL_AUTHENTICATION_KEY,
    USERNAME_LINK_LABEL_ENCRYPTION_KEY, USERNAME_LINK_MAX_PTEXT_SIZE,
};
use crate::{proto, UsernameLinkError};

pub fn create_for_username<R: Rng + CryptoRng>(
    rng: &mut R,
    username: String,
) -> Result<Vec<u8>, UsernameLinkError> {
    let username_data = proto::username::UsernameData { username };
    let ptext = username_data.encode_to_vec();
    if ptext.len() >= USERNAME_LINK_MAX_PTEXT_SIZE {
        return Err(UsernameLinkError::InputDataTooLong);
    }
    let entropy: [u8; USERNAME_LINK_ENTROPY_SIZE] = random_bytes(rng);
    let iv: [u8; USERNAME_LINK_IV_SIZE] = random_bytes(rng);
    let aes_key = hkdf(&entropy, USERNAME_LINK_LABEL_ENCRYPTION_KEY);
    let mac_key = hkdf(&entropy, USERNAME_LINK_LABEL_AUTHENTICATION_KEY);
    let ctext = aes_256_cbc_encrypt(&ptext, &aes_key, &iv).expect("valid key and iv");

    let mut buf: Vec<u8> =
        Vec::with_capacity(USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN + ctext.len());
    buf.extend(iv.as_slice());
    buf.extend(ctext);
    buf.extend(hmac(&mac_key, buf.as_slice()));

    let mut result: Vec<u8> = Vec::with_capacity(USERNAME_LINK_ENTROPY_SIZE + buf.len());
    result.extend(entropy);
    result.extend(buf);
    Ok(result)
}

pub fn decrypt_username(
    entropy: &[u8],
    encrypted_username: &[u8],
) -> Result<String, UsernameLinkError> {
    if entropy.len() != USERNAME_LINK_ENTROPY_SIZE {
        return Err(UsernameLinkError::InvalidEntropyDataLength);
    }
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
    CryptographicMac::new(USERNAME_LINK_HMAC_ALGORITHM, mac_key)
        .expect("known algorithm")
        .update_and_get(input)
        .expect("digest updated successfully")
        .finalize()
        .expect("digest finalized successfully")
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
            create_for_username(&mut csprng, long_username.to_string()),
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
    fn username_link_invalid_entropy_size() {
        let entropy = [0u8; USERNAME_LINK_ENTROPY_SIZE - 1];
        let encrypted_username =
            [0u8; USERNAME_LINK_IV_SIZE + USERNAME_LINK_HMAC_LEN + TEST_CTEXT_SIZE];
        assert!(matches!(
            decrypt_username(&entropy, &encrypted_username),
            Err(UsernameLinkError::InvalidEntropyDataLength)
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
        let result = create_for_username(&mut csprng, expected_username.into()).expect("no error");
        let (entropy, encrypted_username) = result.split_at(USERNAME_LINK_ENTROPY_SIZE);
        let actual_username = decrypt_username(entropy, encrypted_username).expect("no error");
        assert_eq!(expected_username, actual_username);
    }
}
