//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use pqcrypto_ml_kem::ffi::{
    PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES, PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES,
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use super::{KeyMaterial, Public, Secret};
use crate::Result;

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const PUBLIC_KEY_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
    const SECRET_KEY_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES;
    const CIPHERTEXT_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    const SHARED_SECRET_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES;

    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let (pk, sk) = pqcrypto_ml_kem::kyber1024::keypair();
        (
            KeyMaterial::new(pk.as_bytes().into()),
            KeyMaterial::new(sk.as_bytes().into()),
        )
    }

    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (super::SharedSecret, super::RawCiphertext) {
        let mlkem_pk = pqcrypto_ml_kem::kyber1024::PublicKey::from_bytes(pub_key)
            .expect("valid ML-KEM 1024 public key bytes");
        let (mlkem_ss, mlkem_ct) = pqcrypto_ml_kem::kyber1024::encapsulate(&mlkem_pk);
        (mlkem_ss.as_bytes().into(), mlkem_ct.as_bytes().into())
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<super::SharedSecret> {
        let mlkem_sk = pqcrypto_ml_kem::kyber1024::SecretKey::from_bytes(secret_key)
            .expect("valid ML-KEM 1024 secret key bytes");
        let mlkem_ct = pqcrypto_ml_kem::kyber1024::Ciphertext::from_bytes(ciphertext)
            .expect("valid ML-KEM 1024 ciphertext");
        let mlkem_ss = pqcrypto_ml_kem::kyber1024::decapsulate(&mlkem_ct, &mlkem_sk);

        Ok(mlkem_ss.as_bytes().into())
    }
}
