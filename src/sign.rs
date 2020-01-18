//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

use crate::args::*;
use crate::errors::*;
use crate::statement::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

// Signatures are such a common ZKP that we provide special functions for them:
pub fn sign(
    private_key: Scalar,
    public_key: RistrettoPoint,
    message: &[u8],
    randomness: &[u8],
) -> Result<Vec<u8>, PokshoError> {
    let mut st = Statement::new();
    st.add("public_key", &[("private_key", "G")]);

    let mut scalar_args = ScalarArgs::new();
    scalar_args.add("private_key", private_key);

    let mut point_args = PointArgs::new();
    point_args.add("public_key", public_key);

    st.prove(&scalar_args, &point_args, &message, randomness)
}

pub fn verify_signature(
    signature: &[u8],
    public_key: RistrettoPoint,
    message: &[u8],
) -> Result<(), PokshoError> {
    let mut st = Statement::new();
    st.add("public_key", &[("private_key", "G")]);

    let mut point_args = PointArgs::new();
    point_args.add("public_key", public_key);

    st.verify_proof(signature, &point_args, &message)
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]

    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn test_signature() {
        let mut block64 = [0u8; 64];
        let mut block32 = [0u8; 32];
        let mut block100 = [0u8; 100];
        for i in 0..32 {
            block32[i] = i as u8;
        }
        for i in 0..64 {
            block64[i] = i as u8;
        }
        for i in 0..100 {
            block100[i] = i as u8;
        }

        let a = Scalar::from_bytes_mod_order_wide(&block64);
        let A = a * RISTRETTO_BASEPOINT_POINT;
        let randomness = block32;
        let message = block100;
        let signature = sign(a, A, &message, &randomness).unwrap();
        verify_signature(&signature, A, &message).unwrap();
        assert!(
            signature
                == vec![
                    55, 115, 0, 221, 89, 117, 63, 224, 6, 146, 3, 93, 81, 219, 167, 180, 72, 15,
                    166, 166, 195, 91, 6, 207, 76, 221, 221, 80, 187, 181, 95, 10, 218, 175, 63,
                    216, 95, 249, 147, 58, 128, 66, 13, 89, 66, 186, 95, 14, 225, 243, 73, 11, 117,
                    166, 147, 162, 105, 174, 244, 65, 208, 79, 248, 11
                ]
        );
    }
}
