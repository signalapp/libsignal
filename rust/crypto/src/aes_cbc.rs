//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes::Aes256;
use std::result::Result;

use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum EncryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum DecryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// These cases should not be distinguished; message corruption can cause either problem.
    BadCiphertext(&'static str),
}

pub fn aes_256_cbc_encrypt(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    Cbc::<Aes256, Pkcs7>::new_from_slices(key, iv)
        .map_err(|_| EncryptionError::BadKeyOrIv)
        .map(|mode| mode.encrypt_vec(ptext))
}

pub fn aes_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(DecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
        ));
    }

    Cbc::<Aes256, Pkcs7>::new_from_slices(key, iv)
        .map_err(|_| DecryptionError::BadKeyOrIv)?
        .decrypt_vec(ctext)
        .map_err(|_| DecryptionError::BadCiphertext("failed to decrypt"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes_cbc_test() {
        let key = hex::decode("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
            .expect("valid hex");
        let iv = hex::decode("6f8a557ddc0a140c878063a6d5f31d3d").expect("valid hex");

        let ptext = hex::decode("30736294a124482a4159").expect("valid hex");

        let ctext = aes_256_cbc_encrypt(&ptext, &key, &iv).expect("valid key and IV");
        assert_eq!(
            hex::encode(ctext.clone()),
            "dd3f573ab4508b9ed0e45e0baf5608f3"
        );

        let recovered = aes_256_cbc_decrypt(&ctext, &key, &iv).expect("valid");
        assert_eq!(hex::encode(ptext), hex::encode(recovered.clone()));

        // padding is invalid:
        assert!(aes_256_cbc_decrypt(&recovered, &key, &iv).is_err());
        assert!(aes_256_cbc_decrypt(&ctext, &key, &ctext).is_err());

        // bitflip the IV to cause a change in the recovered text
        let bad_iv = hex::decode("ef8a557ddc0a140c878063a6d5f31d3d").expect("valid hex");
        let recovered = aes_256_cbc_decrypt(&ctext, &key, &bad_iv).expect("still valid");
        assert_eq!(hex::encode(recovered), "b0736294a124482a4159");
    }
}
