//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libcrux_ml_kem::SHARED_SECRET_SIZE;
use libcrux_ml_kem::mlkem1024::{
    self, MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
};
use rand::Rng as _;

use super::{
    BadKEMKeyLength, ConstantLength as _, DecapsulateError, KeyMaterial, KeyType, Public, Secret,
};

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const KEY_TYPE: KeyType = KeyType::Kyber1024;
    const PUBLIC_KEY_LENGTH: usize = MlKem1024PublicKey::LENGTH;
    const SECRET_KEY_LENGTH: usize = MlKem1024PrivateKey::LENGTH;
    const CIPHERTEXT_LENGTH: usize = MlKem1024Ciphertext::LENGTH;
    const SHARED_SECRET_LENGTH: usize = SHARED_SECRET_SIZE;

    fn generate<R: rand::CryptoRng + ?Sized>(
        csprng: &mut R,
    ) -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let (sk, pk) = mlkem1024::generate_key_pair(csprng.random()).into_parts();
        (KeyMaterial::from(pk), KeyMaterial::from(sk))
    }

    fn encapsulate<R: rand::CryptoRng + ?Sized>(
        pub_key: &KeyMaterial<Public>,
        csprng: &mut R,
    ) -> Result<(Box<[u8]>, Box<[u8]>), BadKEMKeyLength> {
        let mlkem_pk =
            MlKem1024PublicKey::try_from(pub_key.as_ref()).map_err(|_| BadKEMKeyLength)?;
        let (mlkem_ct, mlkem_ss) = mlkem1024::encapsulate(&mlkem_pk, csprng.random());
        Ok((mlkem_ss.as_ref().into(), mlkem_ct.as_ref().into()))
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<Box<[u8]>, DecapsulateError> {
        let mlkem_sk = MlKem1024PrivateKey::try_from(secret_key.as_ref())
            .map_err(|_| DecapsulateError::BadKeyLength)?;
        let mlkem_ct = MlKem1024Ciphertext::try_from(ciphertext)
            .map_err(|_| DecapsulateError::BadCiphertext)?;
        let mlkem_ss = mlkem1024::decapsulate(&mlkem_sk, &mlkem_ct);

        Ok(mlkem_ss.as_ref().into())
    }
}
