//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{error::Result, SignalProtocolError};

use aes::cipher::stream::{NewStreamCipher, SyncStreamCipher};
use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use ctr::Ctr128;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

pub fn aes_256_ctr_encrypt(ptext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(SignalProtocolError::InvalidCipherCryptographicParameters(
            32, 0,
        ));
    }

    let zero_nonce = [0u8; 16];
    let mut cipher = Ctr128::<Aes256>::new(key.into(), (&zero_nonce).into());

    let mut ctext = ptext.to_vec();
    cipher.apply_keystream(&mut ctext);
    Ok(ctext)
}

pub fn aes_256_ctr_decrypt(ctext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    aes_256_ctr_encrypt(ctext, key)
}

pub fn aes_256_cbc_encrypt(ptext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    match Cbc::<Aes256, Pkcs7>::new_var(key, iv) {
        Ok(mode) => Ok(mode.encrypt_vec(&ptext)),
        Err(block_modes::InvalidKeyIvLength) => Err(
            SignalProtocolError::InvalidCipherCryptographicParameters(key.len(), iv.len()),
        ),
    }
}

pub fn aes_256_cbc_decrypt(ctext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(SignalProtocolError::InvalidCiphertext);
    }

    let mode = match Cbc::<Aes256, Pkcs7>::new_var(key, iv) {
        Ok(mode) => mode,
        Err(block_modes::InvalidKeyIvLength) => {
            return Err(SignalProtocolError::InvalidCipherCryptographicParameters(
                key.len(),
                iv.len(),
            ))
        }
    };

    Ok(mode
        .decrypt_vec(ctext)
        .map_err(|_| SignalProtocolError::InvalidCiphertext)?)
}

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
    let mut hmac = Hmac::<Sha256>::new_varkey(key).expect("HMAC-SHA256 should accept any size key");
    hmac.update(input);
    Ok(hmac.finalize().into_bytes().into())
}

#[cfg(test)]
mod test {

    #[test]
    fn aes_cbc_test() {
        let key = hex::decode("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
            .unwrap();
        let iv = hex::decode("6f8a557ddc0a140c878063a6d5f31d3d").unwrap();

        let ptext = hex::decode("30736294a124482a4159").unwrap();

        let ctext = super::aes_256_cbc_encrypt(&ptext, &key, &iv).unwrap();
        assert_eq!(
            hex::encode(ctext.clone()),
            "dd3f573ab4508b9ed0e45e0baf5608f3"
        );

        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &iv).unwrap();
        assert_eq!(hex::encode(ptext), hex::encode(recovered.clone()));

        // padding is invalid:
        assert!(super::aes_256_cbc_decrypt(&recovered, &key, &iv).is_err());
        assert!(super::aes_256_cbc_decrypt(&ctext, &key, &ctext).is_err());

        // bitflip the IV to cause a change in the recovered text
        let bad_iv = hex::decode("ef8a557ddc0a140c878063a6d5f31d3d").unwrap();
        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &bad_iv).unwrap();
        assert_eq!(hex::encode(recovered), "b0736294a124482a4159");
    }

    #[test]
    fn aes_ctr_test() {
        let key = hex::decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
            .unwrap();
        let ptext = [0u8; 35];

        let ctext = super::aes_256_ctr_encrypt(&ptext, &key).unwrap();
        assert_eq!(
            hex::encode(ctext.clone()),
            "e568f68194cf76d6174d4cc04310a85491151e5d0b7a1f1bc0d7acd0ae3e51e4170e23"
        );
    }
}
