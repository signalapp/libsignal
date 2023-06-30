//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;
use std::result::Result;

use aes::cipher::{NewCipher, StreamCipher};
use aes::Aes256Ctr;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub(crate) enum EncryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
}

#[derive(Debug)]
pub(crate) enum DecryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// Either the input is malformed, or the MAC doesn't match on decryption.
    ///
    /// These cases should not be distinguished; message corruption can cause either problem.
    BadCiphertext(&'static str),
}

fn aes_256_ctr_encrypt(ptext: &[u8], key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let key: [u8; 32] = key.try_into().map_err(|_| EncryptionError::BadKeyOrIv)?;

    let zero_nonce = [0u8; 16];
    let mut cipher = Aes256Ctr::new(key[..].into(), zero_nonce[..].into());

    let mut ctext = ptext.to_vec();
    cipher.apply_keystream(&mut ctext);
    Ok(ctext)
}

fn aes_256_ctr_decrypt(ctext: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    aes_256_ctr_encrypt(ctext, key).map_err(|e| match e {
        EncryptionError::BadKeyOrIv => DecryptionError::BadKeyOrIv,
    })
}

pub(crate) fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 should accept any size key");
    hmac.update(input);
    hmac.finalize().into_bytes().into()
}

pub(crate) fn aes256_ctr_hmacsha256_encrypt(
    msg: &[u8],
    cipher_key: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let mut ctext = aes_256_ctr_encrypt(msg, cipher_key)?;
    let mac = hmac_sha256(mac_key, &ctext);
    ctext.extend_from_slice(&mac[..10]);
    Ok(ctext)
}

pub(crate) fn aes256_ctr_hmacsha256_decrypt(
    ctext: &[u8],
    cipher_key: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ctext.len() < 10 {
        return Err(DecryptionError::BadCiphertext("truncated ciphertext"));
    }
    let ptext_len = ctext.len() - 10;
    let our_mac = hmac_sha256(mac_key, &ctext[..ptext_len]);
    let same: bool = our_mac[..10].ct_eq(&ctext[ptext_len..]).into();
    if !same {
        return Err(DecryptionError::BadCiphertext("MAC verification failed"));
    }
    aes_256_ctr_decrypt(&ctext[..ptext_len], cipher_key)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes_ctr_test() {
        let key = hex::decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
            .expect("valid hex");
        let ptext = [0u8; 35];

        let ctext = aes_256_ctr_encrypt(&ptext, &key).expect("valid key");
        assert_eq!(
            hex::encode(ctext),
            "e568f68194cf76d6174d4cc04310a85491151e5d0b7a1f1bc0d7acd0ae3e51e4170e23"
        );
    }
}
