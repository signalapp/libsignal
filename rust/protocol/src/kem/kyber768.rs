//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libcrux_ml_kem::mlkem768::{MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_ml_kem::{kyber768, MlKemCiphertext, SHARED_SECRET_SIZE};
use rand::rngs::OsRng;
use rand::{Rng as _, TryRngCore as _};

use super::{KeyMaterial, Public, Secret};
use crate::kem::ConstantLength as _;
use crate::Result;

pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    const PUBLIC_KEY_LENGTH: usize = MlKem768PublicKey::LENGTH;
    const SECRET_KEY_LENGTH: usize = MlKem768PrivateKey::LENGTH;
    const CIPHERTEXT_LENGTH: usize = MlKem768Ciphertext::LENGTH;
    const SHARED_SECRET_LENGTH: usize = SHARED_SECRET_SIZE;

    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        let (sk, pk) = kyber768::generate_key_pair(OsRng.unwrap_err().random()).into_parts();
        (KeyMaterial::from(pk), KeyMaterial::from(sk))
    }

    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (super::SharedSecret, super::RawCiphertext) {
        let kyber_pk =
            MlKem768PublicKey::try_from(pub_key.as_ref()).expect("valid kyber768 public key bytes");
        let (kyber_ct, kyber_ss) = kyber768::encapsulate(&kyber_pk, OsRng.unwrap_err().random());
        (kyber_ss.as_ref().into(), kyber_ct.as_ref().into())
    }

    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<super::SharedSecret> {
        let kyber_sk = MlKem768PrivateKey::try_from(secret_key.as_ref())
            .expect("valid kyber768 secret key bytes");
        let kyber_ct = MlKemCiphertext::try_from(ciphertext).expect("valid kyber768 ciphertext");
        let kyber_ss = kyber768::decapsulate(&kyber_sk, &kyber_ct);

        Ok(kyber_ss.as_ref().into())
    }
}
