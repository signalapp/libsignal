//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::iter::repeat_with;
use std::num::{NonZeroU32, NonZeroUsize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};

use crate::errors::Error;
use crate::proto::svr4::{self, request4};

/// Make a request to remove a record from SVR4.
#[allow(dead_code)]
pub fn make_remove4_request() -> Vec<u8> {
    svr4::Request4 {
        inner: Some(svr4::request4::Inner::Remove(svr4::request4::Remove {})),
    }
    .encode_to_vec()
}

/// Returns a list of `n` scalars which are chosen randomly but
/// which will sum up to `s`.
fn scalars_summing_to<R: CryptoRngCore>(n: NonZeroUsize, s: Scalar, rng: &mut R) -> Vec<Scalar> {
    let mut v: Vec<Scalar> = repeat_with(|| Scalar::random(rng))
        .take(n.get() - 1)
        .collect();
    let sum: Scalar = v.iter().sum();
    v.push(Scalar::ZERO - sum + s);
    v
}

/// Return a list of `n` byte vectors which are chosen randomly
/// but which will XOR together to `b`.
fn bytes_xoring_to<R: CryptoRngCore>(n: NonZeroUsize, b: &[u8], rng: &mut R) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = repeat_with(|| {
        let mut e = vec![0; b.len()];
        rng.fill_bytes(e.as_mut_slice());
        e
    })
    .take(n.get() - 1)
    .collect();
    let mut xor: Vec<u8> = b.into();
    for vec in v.iter() {
        for (i, c) in vec.iter().enumerate() {
            xor[i] ^= c;
        }
    }
    v.push(xor);
    v
}

/// Key Derivation Function used throughout the rest of this code.
fn kdf(input1: &[u8], input2: &[u8]) -> [u8; 64] {
    // TODO: implement actual KDF
    let mut h = Sha512::new();
    h.update(input1);
    h.update(input2);
    h.finalize().into()
}

/// Helper struct to wrap up the input (the hash'd password) and the
/// OPRF key and provide functionality to derive other things from
/// them based on server ID.
struct OprfAndInput {
    input: Vec<u8>,
    k_oprf: Scalar,
    server_ids: Vec<u64>,
}

impl OprfAndInput {
    /// Return a set of (private, public) auth commitments based on the auth secret.
    fn auth_commitments(&self) -> Vec<(Scalar, RistrettoPoint)> {
        let k_auth = self.auth_secret();
        self.server_ids
            .iter()
            .map(|id| kdf(&k_auth, &id.to_be_bytes()))
            .map(|k| Scalar::hash_from_bytes::<Sha512>(&k))
            .map(|s| (s, RISTRETTO_BASEPOINT_TABLE * &s))
            .collect()
    }

    /// Returns the Ristretto point used for authentication.
    fn auth_pt(&self) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_TABLE * &self.k_oprf
    }

    /// Returns the secret used for authentication.
    fn auth_secret(&self) -> [u8; 64] {
        kdf(&self.input, &self.auth_pt().compress().to_bytes())
    }

    /// Returns a (new every time) set of Ristretto scalars which sum to k_oprf
    /// and can be distributed across SVR instances.
    fn oprf_keyshares<R: CryptoRngCore>(&self, rng: &mut R) -> Vec<Scalar> {
        scalars_summing_to(
            NonZeroUsize::new(self.server_ids.len()).unwrap(),
            self.k_oprf,
            rng,
        )
    }
}

#[allow(dead_code)]
pub struct Backup4 {
    oprf_and_input: OprfAndInput,
    s_enc: [u8; 32],
    pub requests: Vec<Vec<u8>>,
}

impl Backup4 {
    pub fn new<R: CryptoRngCore>(
        server_ids: &[u64],
        input: &[u8],
        max_tries: NonZeroU32,
        rng: &mut R,
    ) -> Result<Self, Error> {
        assert!(!server_ids.is_empty());
        let k_oprf = Scalar::random(rng);

        let oi = OprfAndInput {
            server_ids: server_ids.to_vec(),
            k_oprf,
            input: input.to_vec(),
        };

        let mut s_enc = [0u8; 32];
        rng.fill_bytes(&mut s_enc);

        let oprf_keyshares = oi.oprf_keyshares(rng);
        let enc_keyshares =
            bytes_xoring_to(NonZeroUsize::new(oi.server_ids.len()).unwrap(), &s_enc, rng);
        let zero_keyshares = scalars_summing_to(
            NonZeroUsize::new(oi.server_ids.len()).unwrap(),
            Scalar::ZERO,
            rng,
        );

        let auth_commitments = oi.auth_commitments();
        let version = rng.next_u64();

        let requests: Vec<Vec<u8>> = (0usize..server_ids.len())
            .map(|i| svr4::Request4 {
                inner: Some(svr4::request4::Inner::Create(request4::Create {
                    version,
                    max_tries: max_tries.get(),
                    oprf_secretshare: oprf_keyshares[i].to_bytes().to_vec(),
                    auth_commitment: auth_commitments[i].1.compress().to_bytes().to_vec(),
                    encryption_secretshare: enc_keyshares[i].clone(),
                    zero_secretshare: zero_keyshares[i].to_bytes().to_vec(),
                })),
            })
            .map(|cr| cr.encode_to_vec())
            .collect();

        Ok(Self {
            oprf_and_input: oi,
            s_enc,
            requests,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use hex_literal::hex;
    use proptest::proptest;
    use rand_core::OsRng;

    #[test]
    fn scalars_summing_to_works() {
        proptest!(|(n in 1usize..10)| {
            let mut rng = OsRng;
            let want = Scalar::random(&mut rng);
            let out = scalars_summing_to(NonZeroUsize::new(n).unwrap(), want, &mut rng);
            let got: Scalar = out.iter().sum();
            assert_eq!(got, want);
            assert_eq!(out.len(), n);
        });
    }

    #[test]
    fn bytes_xoring_to_works() {
        let want = vec![1u8; 32];
        proptest!(|(n in 1usize..10)|{
            let mut rng = OsRng;
            let out: Vec<Vec<u8>> =
                bytes_xoring_to(NonZeroUsize::new(n).unwrap(), &want, &mut rng);
            let mut got = vec![0u8; 32];
            for vec in out.iter() {
                for (i, c) in vec.iter().enumerate() {
                    got[i] ^= c;
                }
            }
            assert_eq!(got, want);
            assert_eq!(out.len(), n);
        });
    }

    #[test]
    fn oai_generates_consistent_auth_key_given_constant_inputs() {
        let oai = OprfAndInput {
            input: vec![1u8; 64],
            k_oprf: Scalar::ONE,
            server_ids: vec![1, 2, 3],
        };
        let got = oai.auth_secret();
        let want = hex!(
            "
            b8fe63ebac3c5c0292ddc84f361a93c2
            d2e84d6d50b4a29ddbadc820b70087a7
            aff86180c6523db25e7cd63c47eef815
            439be77aa57d067cbb4bee4dc198f4c6
        "
        );
        assert_eq!(want, got);
    }
}
