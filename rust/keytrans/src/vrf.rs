//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implements ECVRF-EDWARDS25519-SHA512-TAI from RFC 9381.
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use sha2::{Digest as _, Sha512};

const SUITE_ID: u8 = 0x03;
const DOMAIN_SEPARATOR_ENCODE: u8 = 0x01;
const DOMAIN_SEPARATOR_CHALLENGE: u8 = 0x02;
const DOMAIN_SEPARATOR_PROOF: u8 = 0x03;
const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// Invalid point on curve
    InvalidCurvePoint,
    /// Invalid VRF proof
    InvalidProof,
}

type Result<T> = std::result::Result<T, Error>;

fn encode_to_curve_try_and_increment(salt: &[u8], data: &[u8]) -> EdwardsPoint {
    let mut i = 0;
    let mut hasher = Sha512::new();

    loop {
        hasher.update([SUITE_ID, DOMAIN_SEPARATOR_ENCODE]);
        hasher.update(salt);
        hasher.update(data);
        hasher.update([i, DOMAIN_SEPARATOR_BACK]);

        let r = hasher.finalize_reset();
        match CompressedEdwardsY(r[..32].try_into().expect("hash has enough bytes")).decompress() {
            Some(pt) => return pt.mul_by_cofactor(),
            None => i += 1,
        }
    }
}

fn generate_challenge(pts: [&[u8; 32]; 5]) -> [u8; 16] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_ID, DOMAIN_SEPARATOR_CHALLENGE]);
    for pt in pts {
        hasher.update(pt);
    }
    hasher.update([DOMAIN_SEPARATOR_BACK]);
    let c = hasher.finalize();

    c[..16].try_into().expect("hash has enough bytes")
}

fn proof_to_hash(gamma: &EdwardsPoint) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_ID, DOMAIN_SEPARATOR_PROOF]);
    hasher.update(gamma.mul_by_cofactor().compress().0);
    hasher.update([DOMAIN_SEPARATOR_BACK]);
    let index = hasher.finalize();

    index[..32].try_into().expect("hash has enough bytes")
}

/// PublicKey holds a VRF public key.
#[derive(Clone)]
pub struct PublicKey {
    compressed: [u8; 32],
    decompressed: EdwardsPoint,
}

impl TryFrom<[u8; 32]> for PublicKey {
    type Error = Error;

    fn try_from(public_key: [u8; 32]) -> Result<Self> {
        match CompressedEdwardsY(public_key).decompress() {
            Some(pt) => Ok(PublicKey {
                compressed: public_key,
                decompressed: pt,
            }),
            None => Err(Error::InvalidCurvePoint),
        }
    }
}

impl PublicKey {
    /// Checks that proof is the correct VRF proof for message m, and outputs
    /// the index if so.
    pub fn proof_to_hash(&self, m: &[u8], proof: &[u8; 80]) -> Result<[u8; 32]> {
        // Decode proof into its component parts: gamma, c, and s.
        let gamma = CompressedEdwardsY(proof[..32].try_into().expect("proof has enough bytes"))
            .decompress()
            .ok_or(Error::InvalidProof)?;

        let mut c_bytes = [0u8; 32];
        c_bytes[..16].copy_from_slice(&proof[32..48]);
        let c = -Scalar::from_canonical_bytes(c_bytes)
            .into_option()
            .ok_or(Error::InvalidProof)?;

        let s =
            Scalar::from_canonical_bytes(proof[48..80].try_into().expect("proof has enough bytes"))
                .into_option()
                .ok_or(Error::InvalidProof)?;

        // H = encode_to_curve_try_and_increment(pk, m)
        // U = [s]B - [c]Y
        // V = [s]H - [c]Gamma
        let h = encode_to_curve_try_and_increment(&self.compressed, m);

        let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, &self.decompressed, &s);
        let v = EdwardsPoint::vartime_multiscalar_mul(&[s, c], &[h, gamma]);

        // Check challenge.
        let c_prime = generate_challenge([
            &self.compressed,
            &h.compress().0,
            proof[..32].try_into().expect("proof has enough bytes"),
            &u.compress().0,
            &v.compress().0,
        ]);
        if proof[32..48] != c_prime {
            return Err(Error::InvalidProof);
        }

        Ok(proof_to_hash(&gamma))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.compressed
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    struct TestVector {
        pk: [u8; 32],
        alpha: &'static [u8],
        h: [u8; 32],
        pi: [u8; 80],
        beta: [u8; 32],
    }

    const TEST_VECTORS: [TestVector; 3] = [
        TestVector {
            pk: hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            alpha: &hex!(""),
            h: hex!("91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318"),
            pi: hex!("8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805"),
            beta: hex!("90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff"),
        },
        TestVector {
            pk: hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            alpha: &hex!("72"),
            h: hex!("5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551"),
            pi: hex!("f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02"),
            beta: hex!("eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb"),
        },
        TestVector {
            pk: hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            alpha: &hex!("af82"),
            h: hex!("bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a"),
            pi: hex!("9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e"),
            beta: hex!("645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45"),
        },
    ];

    #[test]
    fn test_encode_to_curve_try_and_increment() {
        for v in TEST_VECTORS {
            let got = encode_to_curve_try_and_increment(&v.pk, v.alpha)
                .compress()
                .0;
            assert_eq!(got, v.h);
        }
    }

    #[test]
    fn test_proof_to_hash() {
        for v in TEST_VECTORS {
            let pk = PublicKey::try_from(v.pk).unwrap();
            let index = pk.proof_to_hash(v.alpha, &v.pi).unwrap();
            assert_eq!(index, v.beta);
        }
    }

    #[test]
    fn test_proof_to_hash_fails() {
        for v in TEST_VECTORS {
            let pk = PublicKey::try_from(v.pk).unwrap();

            assert!(pk.proof_to_hash(b"a", &v.pi).is_err());

            for i in 0..v.pi.len() {
                let mut pi = v.pi;
                pi[i] ^= 1;
                assert!(pk.proof_to_hash(v.alpha, &pi).is_err());
            }
        }
    }
}
