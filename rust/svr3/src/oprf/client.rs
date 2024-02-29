//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};

use super::ciphersuite::hash_to_group;
use super::errors::OPRFError;
use super::util::i2osp_u16;

pub fn apply_blind(oprf_input: &[u8], blind: &Scalar) -> RistrettoPoint {
    let input_element = hash_to_group(oprf_input);
    blind * input_element
}

pub fn blind<R: CryptoRngCore>(
    oprf_input: &[u8],
    rng: &mut R,
) -> Result<(Scalar, RistrettoPoint), OPRFError> {
    let blind = Scalar::random(rng);

    let blinded_element = apply_blind(oprf_input, &blind);
    if blinded_element == RistrettoPoint::identity() {
        Err(OPRFError::BlindError)
    } else {
        Ok((blind, blinded_element))
    }
}

pub fn finalize(oprf_input: &[u8], blind: &Scalar, evaluated_element: &RistrettoPoint) -> [u8; 64] {
    let unblinded_element = blind.invert() * evaluated_element;
    let compressed = unblinded_element.compress();
    let unblinded_bytes = compressed.as_bytes();

    let hasher = Sha512::new();

    hasher
        .chain_update(i2osp_u16(oprf_input.len().try_into().unwrap()))
        .chain_update(oprf_input)
        .chain_update(i2osp_u16(unblinded_bytes.len().try_into().unwrap()))
        .chain_update(unblinded_bytes)
        .chain_update("Finalize")
        .finalize()
        .as_slice()
        .try_into()
        .expect("Wrong length")
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use hex_literal::hex;

    use crate::oprf::ciphersuite::tests::derive_key_pair;
    use crate::oprf::client::{apply_blind, finalize};

    fn blind_evaluate(sk: &Scalar, blinded_element: &RistrettoPoint) -> RistrettoPoint {
        sk * blinded_element
    }

    fn ietf_test(
        seed: &[u8],
        key_info: &[u8],
        sk_expected: [u8; 32],
        input: &[u8],
        blind_bytes: [u8; 32],
        blinded_element_expected: &[u8],
        evaluated_element_expected: &[u8],
        output_expected: &[u8],
    ) {
        let blind = Scalar::from_bytes_mod_order(blind_bytes);
        let (sk, _) = derive_key_pair(seed, key_info).unwrap();

        assert_eq!(sk, Scalar::from_bytes_mod_order(sk_expected));
        let blinded_element = apply_blind(input, &blind);

        let compressed_blinded = blinded_element.compress();
        assert_eq!(compressed_blinded.as_bytes(), &blinded_element_expected);

        let evaluated_element = blind_evaluate(&sk, &blinded_element);
        let compressed_evaluated = evaluated_element.compress();
        assert_eq!(compressed_evaluated.as_bytes(), &evaluated_element_expected);

        let output = finalize(input, &blind, &evaluated_element);
        assert_eq!(output, output_expected);
    }

    #[test]
    fn ietf_a_1_1_1() {
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

        let input = hex!("00");

        let blind_bytes = hex!(
            "
        64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706
        "
        );

        let blinded_element_expected = hex!(
            "
        609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c
        "
        );

        let evaluated_element_expected = hex!(
            "
        7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e
        "
        );

        let output_expected = hex!("
        527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6
        ");
        ietf_test(
            &seed,
            &key_info,
            sk_expected,
            &input,
            blind_bytes,
            &blinded_element_expected,
            &evaluated_element_expected,
            &output_expected,
        )
    }

    #[test]
    fn ietf_a_1_1_2() {
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

        let input = hex!("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");

        let blind_bytes = hex!(
            "
        64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706
        "
        );

        let blinded_element_expected = hex!(
            "
        da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418
        "
        );

        let evaluated_element_expected = hex!(
            "
            b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25
        "
        );

        let output_expected = hex!("
        f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73
        ");
        ietf_test(
            &seed,
            &key_info,
            sk_expected,
            &input,
            blind_bytes,
            &blinded_element_expected,
            &evaluated_element_expected,
            &output_expected,
        )
    }
}
