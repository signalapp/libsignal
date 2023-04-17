//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Types used in both the issuance and presentation of credentials

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use serde::{Deserialize, Serialize};

use crate::sho::ShoExt;
use crate::RANDOMNESS_LEN;

/// A credential created by the issuing server over a set of attributes.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Serialize, Deserialize)]
pub struct Credential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CredentialPrivateKey {
    pub(crate) w: Scalar,
    pub(crate) wprime: Scalar,
    pub(crate) W: RistrettoPoint,
    pub(crate) x0: Scalar,
    pub(crate) x1: Scalar,
    pub(crate) y: [Scalar; NUM_SUPPORTED_ATTRS],
}

impl CredentialPrivateKey {
    fn generate(randomness: [u8; RANDOMNESS_LEN]) -> Self {
        let mut sho =
            ShoHmacSha256::new(b"Signal_ZKCredential_CredentialPrivateKey_generate_20230410");
        sho.absorb_and_ratchet(&randomness);

        let system = *SYSTEM_PARAMS;
        let w = sho.get_scalar();
        let W = w * system.G_w;
        let wprime = sho.get_scalar();
        let x0 = sho.get_scalar();
        let x1 = sho.get_scalar();
        let y = [(); NUM_SUPPORTED_ATTRS].map(|_| sho.get_scalar());
        Self {
            w,
            wprime,
            W,
            x0,
            x1,
            y,
        }
    }

    /// Implements the credential computation described in Chase-Perrin-Zaverucha section 3.1.
    pub(crate) fn credential_core(&self, M: &[RistrettoPoint], sho: &mut dyn ShoApi) -> Credential {
        assert!(
            M.len() <= NUM_SUPPORTED_ATTRS,
            "more than {} attributes not supported",
            NUM_SUPPORTED_ATTRS
        );
        let t = sho.get_scalar();
        let U = sho.get_point();

        let mut V = self.W + (self.x0 + self.x1 * t) * U;
        for (yn, Mn) in self.y.iter().zip(M) {
            V += yn * Mn;
        }
        Credential { t, U, V }
    }
}

/// A public key used by the client to receive and verify credentials.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialPublicKey {
    pub(crate) C_W: RistrettoPoint,
    /// The value of `I` depends on the total number of attributes used.
    ///
    /// In the original paper, `I` is computed over the maximum number of attributes only, but that
    /// makes presentation proofs larger for credentials that don't use that many attributes. Here
    /// we provide `I_n` for any supported number of attributes. We do skip `I_0`, since that would
    /// be a credential with only public attributes, in which case you could just use a classic MAC.
    I: [RistrettoPoint; NUM_SUPPORTED_ATTRS - 1],
}

impl CredentialPublicKey {
    pub(crate) fn I(&self, num_attrs: usize) -> RistrettoPoint {
        // `- 1` because we would normally want the third entry in the list for a three-attribute
        // credential (the usual conversion from one-based counts to zero-based indexes).
        // `- 1` again because we skip `I_0`; a one-attribute credential would only have public
        // attributes.
        self.I[num_attrs - 2]
    }
}

impl<'a> From<&'a CredentialPrivateKey> for CredentialPublicKey {
    fn from(private_key: &'a CredentialPrivateKey) -> Self {
        let system = *SYSTEM_PARAMS;

        let C_W = private_key.W + (private_key.wprime * system.G_wprime);
        let mut I_i = system.G_V - (private_key.x0 * system.G_x0) - (private_key.x1 * system.G_x1);

        let mut y_and_G_y_iter = private_key.y.iter().zip(system.G_y);
        let (y0, G_y0) = y_and_G_y_iter.next().expect("correct number of parameters");
        I_i -= y0 * G_y0;

        let I = [(); NUM_SUPPORTED_ATTRS - 1].map(|_| {
            let (yn, G_yn) = y_and_G_y_iter.next().expect("correct number of parameters");
            I_i -= yn * G_yn;
            I_i
        });
        debug_assert!(y_and_G_y_iter.next().is_none());

        CredentialPublicKey { C_W, I }
    }
}

/// A key pair used by the issuing server to sign credentials.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Deserialize, Clone)]
#[serde(from = "CredentialPrivateKey")]
pub struct CredentialKeyPair {
    private_key: CredentialPrivateKey,
    public_key: CredentialPublicKey,
}

impl CredentialKeyPair {
    /// Generates a new key pair.
    pub fn generate(randomness: [u8; RANDOMNESS_LEN]) -> Self {
        CredentialPrivateKey::generate(randomness).into()
    }

    pub(crate) fn private_key(&self) -> &CredentialPrivateKey {
        &self.private_key
    }

    /// Gets the public key.
    pub fn public_key(&self) -> &CredentialPublicKey {
        &self.public_key
    }
}

impl From<CredentialPrivateKey> for CredentialKeyPair {
    fn from(private_key: CredentialPrivateKey) -> Self {
        let public_key = CredentialPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

impl Serialize for CredentialKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.private_key.serialize(serializer)
    }
}

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams = SystemParams::generate();
}

pub(crate) const NUM_SUPPORTED_ATTRS: usize = 7; // 1 aggregate public, 3 two-point private

/// Parameters shared by the client and server.
///
/// User code never needs to explicitly reference these.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub(crate) struct SystemParams {
    pub(crate) G_w: RistrettoPoint,
    pub(crate) G_wprime: RistrettoPoint,
    pub(crate) G_x0: RistrettoPoint,
    pub(crate) G_x1: RistrettoPoint,
    pub(crate) G_V: RistrettoPoint,
    pub(crate) G_z: RistrettoPoint,
    pub(crate) G_y: [RistrettoPoint; NUM_SUPPORTED_ATTRS],
}

impl SystemParams {
    /// An arbitrary set of independent points generated through a constant sequence of hash
    /// operations.
    fn generate() -> Self {
        let mut sho = ShoSha256::new(b"Signal_ZKCredential_ConstantSystemParams_generate_20230410");
        let G_w = sho.get_point();
        let G_wprime = sho.get_point();

        let G_x0 = sho.get_point();
        let G_x1 = sho.get_point();

        let G_V = sho.get_point();
        let G_z = sho.get_point();

        let G_y = [(); NUM_SUPPORTED_ATTRS].map(|_| sho.get_point());

        SystemParams {
            G_w,
            G_wprime,
            G_x0,
            G_x1,
            G_V,
            G_z,
            G_y,
        }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }

    #[cfg(test)]
    const SYSTEM_HARDCODED: &[u8] = &[
        0x58, 0x9c, 0x87, 0x18, 0xe8, 0x26, 0x3a, 0x53, 0xa7, 0x89, 0x32, 0xb6, 0x21, 0x2a, 0x46,
        0xe7, 0xfd, 0x52, 0xde, 0x3a, 0xd1, 0x57, 0xb5, 0xbb, 0x27, 0x7d, 0xba, 0x49, 0x4c, 0xfd,
        0x34, 0x71, 0xd4, 0xcc, 0x5f, 0x90, 0x68, 0x59, 0x52, 0x91, 0x7b, 0x33, 0x36, 0x6e, 0xfc,
        0xce, 0x5, 0x12, 0xa1, 0xf8, 0xd7, 0xf, 0x97, 0x47, 0x58, 0x26, 0x6c, 0xb0, 0x4f, 0xc4,
        0x24, 0x34, 0x6d, 0x37, 0xb2, 0xf, 0x49, 0xcb, 0x2a, 0x8, 0x1c, 0x94, 0xb1, 0x77, 0x1f,
        0xd8, 0xc1, 0x72, 0xae, 0x21, 0x78, 0x5c, 0x61, 0xea, 0x2c, 0x7e, 0x31, 0x94, 0x7c, 0xe3,
        0x51, 0xe7, 0xb5, 0xff, 0x7, 0x2, 0x8c, 0x53, 0x29, 0xbe, 0xb8, 0x7b, 0x31, 0x7f, 0xfc,
        0xd9, 0x81, 0xe4, 0x40, 0x81, 0x9d, 0x91, 0x13, 0x6c, 0x98, 0x8d, 0x6d, 0x9f, 0xbe, 0xa4,
        0xa8, 0x7e, 0x55, 0xed, 0x24, 0xa5, 0x99, 0x3a, 0xa0, 0x2f, 0x68, 0x8a, 0xb1, 0xd3, 0xbd,
        0x19, 0x5, 0x6f, 0x94, 0xc8, 0xa4, 0x4b, 0x8f, 0xad, 0xdf, 0xa3, 0xc9, 0xc7, 0x9c, 0x95,
        0xad, 0x44, 0x31, 0x1a, 0x7b, 0xf0, 0xe, 0x5e, 0x86, 0x2e, 0xc2, 0xc3, 0x99, 0xf0, 0xd6,
        0x89, 0xdf, 0xb8, 0xc2, 0xdc, 0xd, 0x7c, 0xab, 0xa3, 0x2a, 0xfc, 0xf5, 0x8c, 0xf0, 0xd8,
        0x5f, 0x78, 0x19, 0x5a, 0xb, 0x5a, 0xb7, 0x32, 0xf5, 0x65, 0x59, 0x54, 0x92, 0xcf, 0xd9,
        0x82, 0x32, 0x1d, 0x1f, 0x9b, 0xe4, 0xb2, 0x1f, 0xe6, 0xa0, 0x21, 0x43, 0x6, 0x2, 0x3d,
        0x6a, 0x5, 0xd0, 0xd2, 0x3f, 0x67, 0xdd, 0xc1, 0xc0, 0x40, 0xe, 0x5e, 0xa, 0x5e, 0x92,
        0xd1, 0x75, 0x95, 0x13, 0x1b, 0x7a, 0x9, 0x5e, 0x74, 0xb, 0x88, 0x4b, 0x8c, 0x9b, 0xb0,
        0x22, 0x6a, 0x39, 0xcf, 0xd0, 0x27, 0xc7, 0x69, 0xc4, 0xf4, 0x67, 0x7c, 0x51, 0xf2, 0x1b,
        0x24, 0xda, 0x81, 0xfb, 0x2b, 0xd1, 0x35, 0x6a, 0x9d, 0x6, 0x50, 0xf6, 0xa6, 0x3f, 0xcc,
        0x90, 0xd9, 0x3b, 0xd7, 0x4a, 0x95, 0x4b, 0xa6, 0xf7, 0x5f, 0xe, 0x9f, 0xca, 0x47, 0xa6,
        0xd2, 0x17, 0x34, 0xbc, 0xe7, 0xb2, 0x8f, 0x6, 0xb7, 0x6e, 0xf2, 0xc4, 0x4d, 0x20, 0xa0,
        0x70, 0x26, 0x53, 0x4e, 0x58, 0x6e, 0xb8, 0xe1, 0x3, 0x88, 0x74, 0xa9, 0x3e, 0x44, 0xde,
        0x36, 0x2c, 0xe7, 0xbc, 0x8, 0x44, 0xbf, 0xfc, 0x88, 0xe3, 0x90, 0xc6, 0x25, 0x19, 0xe2,
        0x81, 0xaa, 0x6f, 0xd5, 0x3f, 0xf9, 0xdd, 0xd1, 0xd9, 0xba, 0x30, 0x3c, 0xf7, 0x0, 0x4,
        0x27, 0x8e, 0xa2, 0xae, 0x66, 0xce, 0x5, 0xa2, 0x74, 0x9d, 0x29, 0xeb, 0xa5, 0x6f, 0x3e,
        0xfe, 0x99, 0xe4, 0x29, 0x2, 0x82, 0x5c, 0x47, 0x3d, 0xfc, 0x3c, 0x15, 0x4c, 0x37, 0x62,
        0xd2, 0xe7, 0x6b, 0xd1, 0x3, 0xf6, 0x29, 0xd2, 0x50, 0xb2, 0xd9, 0xd5, 0xc2, 0x43, 0xa4,
        0xcf, 0x8f, 0x3b, 0xe2, 0x1a, 0x84, 0xf1, 0x53, 0xf4, 0x4e, 0x27, 0x33, 0xa1, 0x5, 0xcf,
        0x78, 0xa, 0x20, 0xf0, 0x3d, 0x84, 0xfe, 0x1e, 0xbb, 0xeb, 0xe,
    ];
}

#[test]
fn test_system() {
    let params = SystemParams::generate();
    let serialized = bincode::serialize(&params).expect("can serialize");
    println!("PARAMS = {:#x?}", serialized);
    assert!(serialized == SystemParams::SYSTEM_HARDCODED);
}

#[test]
fn round_trip_key_pair() {
    let key_pair = CredentialKeyPair::generate([0x42; RANDOMNESS_LEN]);
    let serialized = bincode::serialize(&key_pair).unwrap();
    let deserialized: CredentialKeyPair = bincode::deserialize(&serialized).unwrap();
    assert_eq!(&key_pair.public_key.C_W, &deserialized.public_key.C_W);
    assert_eq!(&key_pair.private_key.w, &deserialized.private_key.w);
}
