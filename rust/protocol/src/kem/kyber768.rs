//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libcrux_ml_kem::mlkem768::{MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_ml_kem::{MlKemCiphertext, SHARED_SECRET_SIZE, kyber768};
use rand::{CryptoRng, Rng as _};

use super::{
    BadKEMKeyLength, ConstantLength as _, DecapsulateError, KeyMaterial, KeyType, Public, Secret,
};

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const KEY_TYPE: KeyType = KeyType::Kyber768;
    const PUBLIC_KEY_LENGTH: usize = MlKem768PublicKey::LENGTH;
    const SECRET_KEY_LENGTH: usize = MlKem768PrivateKey::LENGTH;
    const CIPHERTEXT_LENGTH: usize = MlKem768Ciphertext::LENGTH;
    const SHARED_SECRET_LENGTH: usize = SHARED_SECRET_SIZE;

    fn generate<R: CryptoRng + ?Sized>(
        csprng: &mut R,
    ) -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let (sk, pk) = kyber768::generate_key_pair(csprng.random()).into_parts();
        (KeyMaterial::from(pk), KeyMaterial::from(sk))
    }

    fn encapsulate<R: CryptoRng + ?Sized>(
        pub_key: &KeyMaterial<Public>,
        csprng: &mut R,
    ) -> Result<(super::SharedSecret, super::RawCiphertext), BadKEMKeyLength> {
        let kyber_pk =
            MlKem768PublicKey::try_from(pub_key.as_ref()).map_err(|_| BadKEMKeyLength)?;
        let (kyber_ct, kyber_ss) = kyber768::encapsulate(&kyber_pk, csprng.random());
        Ok((kyber_ss.as_ref().into(), kyber_ct.as_ref().into()))
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<Box<[u8]>, DecapsulateError> {
        let kyber_sk = MlKem768PrivateKey::try_from(secret_key.as_ref())
            .map_err(|_| DecapsulateError::BadKeyLength)?;
        let kyber_ct =
            MlKemCiphertext::try_from(ciphertext).map_err(|_| DecapsulateError::BadCiphertext)?;
        let kyber_ss = kyber768::decapsulate(&kyber_sk, &kyber_ct);

        Ok(kyber_ss.as_ref().into())
    }
}
