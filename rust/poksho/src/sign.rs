//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
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

    st.prove(&scalar_args, &point_args, message, randomness)
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

    st.verify_proof(signature, &point_args, message)
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]

    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    #[allow(clippy::needless_range_loop, clippy::unwrap_used)]
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
        /*
        for b in signature.iter() {
            print!("0x{:02x}, ", b);
        }
        println!("");
        */
        assert!(
            signature
                == vec![
                    0xa0, 0x8f, 0x6b, 0x34, 0xa2, 0x82, 0xdd, 0x4c, 0x7c, 0xfc, 0x40, 0xb9, 0x18,
                    0xf2, 0x24, 0xa6, 0xb6, 0x31, 0xca, 0x5f, 0x64, 0x80, 0xa1, 0x0b, 0x42, 0xbd,
                    0x14, 0x08, 0x60, 0x2a, 0x7e, 0x00, 0x8a, 0x23, 0xa1, 0xe3, 0x24, 0x79, 0xbe,
                    0xfb, 0x5e, 0x26, 0xb9, 0xf0, 0xf4, 0xfe, 0x0e, 0x9e, 0x9e, 0x9e, 0xc9, 0xaf,
                    0xad, 0x26, 0x91, 0x43, 0xac, 0xb0, 0x3a, 0x22, 0xc6, 0x36, 0x4f, 0x03,
                ]
        );
    }
}
