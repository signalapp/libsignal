//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use super::util::expand_message_xmd_sha512;
use curve25519_dalek::ristretto::RistrettoPoint;

const HASH_TO_GROUP_DST: &str = "HashToGroup-OPRFV1-\0-ristretto255-SHA512";

pub fn hash_to_group(data: &[u8]) -> RistrettoPoint {
    let dst = HASH_TO_GROUP_DST.as_bytes();
    let mut uniform_bytes = [0u8; 64];
    expand_message_xmd_sha512(data, dst, 64u16, &mut uniform_bytes).unwrap();
    RistrettoPoint::from_uniform_bytes(&uniform_bytes)
}

#[cfg(test)]
pub mod tests {
    use crate::oprf::errors::OPRFError;
    use crate::oprf::util::{expand_message_xmd_sha512, i2osp_u16};
    use curve25519_dalek::constants;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use hex_literal::hex;

    const DERIVE_KEYPAIR_DST: &str = "DeriveKeyPairOPRFV1-\0-ristretto255-SHA512";

    fn is_zero(bytes: &[u8]) -> bool {
        bytes.iter().all(|b| *b == 0)
    }

    pub fn derive_key_pair(
        seed: &[u8],
        info: &[u8],
    ) -> Result<(Scalar, RistrettoPoint), OPRFError> {
        let mut derive_input = Vec::<u8>::with_capacity(seed.len() + info.len() + 3);
        let info_len_u16 = match info.len().try_into() {
            Ok(len) => len,
            Err(_) => {
                return Err(OPRFError::DeriveKeyPairError);
            }
        };
        derive_input.extend_from_slice(seed);
        derive_input.extend_from_slice(&i2osp_u16(info_len_u16));
        derive_input.extend_from_slice(info);
        derive_input.extend_from_slice(&[0u8]);
        let len = derive_input.len();

        let mut uniform_bytes = [0u8; 64];
        for counter in 0..=255u8 {
            derive_input[len - 1] = counter;
            expand_message_xmd_sha512(
                derive_input.as_slice(),
                DERIVE_KEYPAIR_DST.as_bytes(),
                64u16,
                &mut uniform_bytes,
            )
            .unwrap();
            if !is_zero(&uniform_bytes) {
                let sk = Scalar::from_bytes_mod_order_wide(&uniform_bytes);
                let pk = sk * constants::RISTRETTO_BASEPOINT_POINT;
                return Ok((sk, pk));
            }
        }

        Err(OPRFError::DeriveKeyPairError)
    }

    #[test]
    fn test_ietf_a_1_1() {
        let seed = hex!(
            "
        a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
        "
        );
        let key_info = hex!(
            "
        74657374206b6579
        "
        );
        let sk_expected = hex!(
            "
        5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e
        "
        );

        let (sk, _) = derive_key_pair(&seed, &key_info).unwrap();

        assert_eq!(sk, Scalar::from_bytes_mod_order(sk_expected));
    }
}
