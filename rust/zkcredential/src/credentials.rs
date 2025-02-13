//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Types used in both the issuance and presentation of credentials

use std::sync::LazyLock;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use partial_default::PartialDefault;
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use serde::{Deserialize, Serialize};

use crate::sho::ShoExt;
use crate::RANDOMNESS_LEN;

/// A credential created by the issuing server over a set of attributes.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
// This type intentionally does not implement `Copy` to make it harder to
// accidentally duplicate these values.
pub struct Credential {
    pub(crate) t: Scalar,
    pub(crate) U: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
}

/// A secret key used to compute a MAC over a set of attributes
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Serialize, Deserialize, Clone, PartialDefault)]
pub(crate) struct CredentialPrivateKey {
    pub(crate) w: Scalar,
    pub(crate) wprime: Scalar,
    pub(crate) W: RistrettoPoint,
    pub(crate) x0: Scalar,
    pub(crate) x1: Scalar,
    pub(crate) y: [Scalar; NUM_SUPPORTED_ATTRS],
}

impl CredentialPrivateKey {
    /// Creates a new secret key using the given source of random bytes.
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

    /// Produces a MAC over the given attributes.
    ///
    /// Implements the credential computation described in Chase-Perrin-Zaverucha section 3.1.
    ///
    /// # Panics
    /// if more than [`NUM_SUPPORTED_ATTRS`] attributes are passed in.
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
#[derive(Serialize, Deserialize, Clone, PartialDefault)]
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
#[derive(Deserialize, Clone, PartialDefault)]
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

static SYSTEM_PARAMS: LazyLock<SystemParams> = LazyLock::new(SystemParams::generate);

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
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    impl SystemParams {
        const SYSTEM_HARDCODED: &'static [u8] = &hex!("589c8718e8263a53a78932b6212a46e7fd52de3ad157b5bb277dba494cfd3471d4cc5f90685952917b33366efcce0512a1f8d70f974758266cb04fc424346d37b20f49cb2a081c94b1771fd8c172ae21785c61ea2c7e31947ce351e7b5ff07028c5329beb87b317ffcd981e440819d91136c988d6d9fbea4a87e55ed24a5993aa02f688ab1d3bd19056f94c8a44b8faddfa3c9c79c95ad44311a7bf00e5e862ec2c399f0d689dfb8c2dc0d7caba32afcf58cf0d85f78195a0b5ab732f565595492cfd982321d1f9be4b21fe6a0214306023d6a05d0d23f67ddc1c0400e5e0a5e92d17595131b7a095e740b884b8c9bb0226a39cfd027c769c4f4677c51f21b24da81fb2bd1356a9d0650f6a63fcc90d93bd74a954ba6f75f0e9fca47a6d21734bce7b28f06b76ef2c44d20a07026534e586eb8e1038874a93e44de362ce7bc0844bffc88e390c62519e281aa6fd53ff9ddd1d9ba303cf70004278ea2ae66ce05a2749d29eba56f3efe99e42902825c473dfc3c154c3762d2e76bd103f629d250b2d9d5c243a4cf8f3be21a84f153f44e2733a105cf780a20f03d84fe1ebbeb0e");
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
}
