//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::Result;

use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use pqcrypto_kyber::ffi::{
    PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES, PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES, PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES,
};

use super::{KeyMaterial, Public, Secret};

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const PUBLIC_KEY_LENGTH: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES;
    const SECRET_KEY_LENGTH: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES;
    const CIPHERTEXT_LENGTH: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    const SHARED_SECRET_LENGTH: usize = PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES;

    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
        (
            KeyMaterial::new(pk.as_bytes().into()),
            KeyMaterial::new(sk.as_bytes().into()),
        )
    }

    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (super::SharedSecret, super::RawCiphertext) {
        let kyber_pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(pub_key)
            .expect("valid kyber768 public key bytes");
        let (kyber_ss, kyber_ct) = pqcrypto_kyber::kyber768::encapsulate(&kyber_pk);
        (kyber_ss.as_bytes().into(), kyber_ct.as_bytes().into())
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<super::SharedSecret> {
        let kyber_sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(secret_key)
            .expect("valid kyber768 secret key bytes");
        let kyber_ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
            .expect("valid kyber768 ciphertext");
        let kyber_ss = pqcrypto_kyber::kyber768::decapsulate(&kyber_ct, &kyber_sk);

        Ok(kyber_ss.as_bytes().into())
    }
}
