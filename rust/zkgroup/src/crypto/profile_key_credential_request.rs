//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::sho::*;
use crate::crypto::credentials::{
    BlindedExpiringProfileKeyCredential, ExpiringProfileKeyCredential,
};
use crate::crypto::profile_key_struct;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    // private
    pub(crate) y: Scalar,

    // public
    pub(crate) Y: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub(crate) Y: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextWithSecretNonce {
    pub(crate) r1: Scalar,
    pub(crate) r2: Scalar,
    pub(crate) D1: RistrettoPoint,
    pub(crate) D2: RistrettoPoint,
    pub(crate) E1: RistrettoPoint,
    pub(crate) E2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) D1: RistrettoPoint,
    pub(crate) D2: RistrettoPoint,
    pub(crate) E1: RistrettoPoint,
    pub(crate) E2: RistrettoPoint,
}

impl KeyPair {
    pub fn generate(sho: &mut Sho) -> Self {
        let y = sho.get_scalar();
        let Y = y * RISTRETTO_BASEPOINT_POINT;
        KeyPair { y, Y }
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey { Y: self.Y }
    }

    pub fn encrypt(
        &self,
        profile_key_struct: profile_key_struct::ProfileKeyStruct,
        sho: &mut Sho,
    ) -> CiphertextWithSecretNonce {
        let r1 = sho.get_scalar();
        let r2 = sho.get_scalar();
        let D1 = r1 * RISTRETTO_BASEPOINT_POINT;
        let E1 = r2 * RISTRETTO_BASEPOINT_POINT;

        let D2 = r1 * (self.Y) + profile_key_struct.M3;
        let E2 = r2 * (self.Y) + profile_key_struct.M4;

        CiphertextWithSecretNonce {
            r1,
            r2,
            D1,
            D2,
            E1,
            E2,
        }
    }

    pub fn decrypt_blinded_expiring_profile_key_credential(
        &self,
        blinded_expiring_profile_key_credential: BlindedExpiringProfileKeyCredential,
    ) -> ExpiringProfileKeyCredential {
        let V = blinded_expiring_profile_key_credential.S2
            - self.y * blinded_expiring_profile_key_credential.S1;
        ExpiringProfileKeyCredential {
            t: blinded_expiring_profile_key_credential.t,
            U: blinded_expiring_profile_key_credential.U,
            V,
        }
    }
}

impl CiphertextWithSecretNonce {
    pub fn get_ciphertext(&self) -> Ciphertext {
        Ciphertext {
            D1: self.D1,
            D2: self.D2,
            E1: self.E1,
            E2: self.E2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::*;
    use crate::crypto::profile_key_commitment;

    #[test]
    fn test_request_response() {
        let mut sho = Sho::new(b"Test_Profile_Key_Credential_Request", b"");

        // client
        let blind_key_pair = KeyPair::generate(&mut sho);

        // server and client
        let profile_key_struct =
            profile_key_struct::ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
        let _ = profile_key_commitment::CommitmentWithSecretNonce::new(
            profile_key_struct,
            TEST_ARRAY_16,
        );

        // client
        let _ = blind_key_pair.encrypt(profile_key_struct, &mut sho);

        // server
        /*TODO request_ciphertext.verify(c).unwrap();

        let credential_key_pair = credentials::KeyPair::generate(TEST_ARRAY_32_2);
        let uid_bytes = TEST_ARRAY_16;
        let redemption_time = 37;
        let randomness = TEST_ARRAY_32_3;
        let response =
            query.create_response(credential_key_pair, uid_bytes, redemption_time, randomness);

        response
            .verify(
                blind_key_pair,
                credential_key_pair.get_public_key(),
                query.E_D1,
                query.E_D2,
                uid_bytes,
                redemption_time,
            )
            .unwrap();

        let mac = response.get_mac(blind_key_pair);

        let master_key = GroupMasterKey::new(TEST_ARRAY_32_4);
        let uid_enc_key_pair = uid_encryption::KeyPair::derive_from(master_key);
        let profile_enc_key_pair = KeyPair::generate(TEST_ARRAY_32_4);
        let profile_ciphertext = profile_enc_key_pair
            .get_public_key()
            .encrypt(profile_key, TEST_ARRAY_32_4);

        let ppp = profile_presentation_proof::PresentationProof::new(
            mac,
            uid_enc_key_pair,
            credential_key_pair.get_public_key(),
            uid_bytes,
            profile_ciphertext.E_B1,
            profile_ciphertext.E_B2,
            profile_key,
            profile_enc_key_pair.B,
            profile_enc_key_pair.b,
            redemption_time,
            TEST_ARRAY_32_5,
        );

        let uid = uid_encryption::UidStruct::new(uid_bytes);
        let uid_ciphertext = uid_enc_key_pair.encrypt(uid);

        ppp.verify(
            uid_ciphertext,
            uid_enc_key_pair.get_public_key(),
            credential_key_pair,
            redemption_time,
            profile_ciphertext.E_B1,
            profile_ciphertext.E_B2,
            profile_enc_key_pair.B,
        ).unwrap();
        */
    }
}
