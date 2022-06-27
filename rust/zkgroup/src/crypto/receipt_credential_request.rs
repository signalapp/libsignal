//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::common::sho::Sho;
use crate::crypto::credentials;
use crate::crypto::credentials::{BlindedReceiptCredential, ReceiptCredential};
use crate::ReceiptSerialBytes;

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
    pub(crate) D1: RistrettoPoint,
    pub(crate) D2: RistrettoPoint,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) D1: RistrettoPoint,
    pub(crate) D2: RistrettoPoint,
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
        receipt_serial_bytes: ReceiptSerialBytes,
        sho: &mut Sho,
    ) -> CiphertextWithSecretNonce {
        let M2 = credentials::convert_to_point_M2_receipt_serial_bytes(receipt_serial_bytes);
        let r1 = sho.get_scalar();
        let D1 = r1 * RISTRETTO_BASEPOINT_POINT;
        let D2 = r1 * (self.Y) + M2;

        CiphertextWithSecretNonce { r1, D1, D2 }
    }

    pub fn decrypt_blinded_receipt_credential(
        &self,
        blinded_receipt_credential: BlindedReceiptCredential,
    ) -> ReceiptCredential {
        let V = blinded_receipt_credential.S2 - self.y * blinded_receipt_credential.S1;
        ReceiptCredential {
            t: blinded_receipt_credential.t,
            U: blinded_receipt_credential.U,
            V,
        }
    }
}

impl CiphertextWithSecretNonce {
    pub fn get_ciphertext(&self) -> Ciphertext {
        Ciphertext {
            D1: self.D1,
            D2: self.D2,
        }
    }
}
