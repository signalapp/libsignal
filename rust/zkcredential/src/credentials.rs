//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Types used in both the issuance and presentation of credentials

use std::marker::PhantomData;
use std::sync::LazyLock;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use derive_where::derive_where;
use partial_default::PartialDefault;
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use serde::{Deserialize, Serialize};

use crate::RANDOMNESS_LEN;
use crate::sho::ShoExt;

/// A marker trait describing how a [`CredentialKeyPair`] will issue credentials.
///
/// The options are [`StandardMode`] and [`LegacyMode`]. Use [`StandardMode`] unless you have to be
/// compatible with existing credentials, as [`LegacyMode`] does not have as strong security
/// properties.
///
/// The mode must be consistent between the issuing and verifying servers. It is not valid to use a
/// `CredentialKeyPair` in multiple modes; forcibly doing so via (de)serialization will fall into
/// the same security issues as simply using [`LegacyMode`].
pub trait CompatibilityMode: sealed::CompatibilityModeInternal {}

/// A marker type describing how a [`CredentialKeyPair`] will issue credentials.
///
/// See [`CompatibilityMode`] for more information.
pub enum StandardMode {}

/// A marker type describing how a [`CredentialKeyPair`] will issue credentials.
///
/// Use [`StandardMode`] unless you have to be compatible with existing credentials. See
/// [`CompatibilityMode`] for more information.
pub enum LegacyMode {}

/// The "sealed trait" idiom:
/// <https://predr.ag/blog/definitive-guide-to-sealed-traits-in-rust/#sealing-traits-with-a-supertrait>
///
/// The types in this module are *usable* in `pub` code, but not nameable by external crates.
mod sealed {
    use super::*;

    /// A value-level representation of [`CompatibilityMode`] implementers.
    ///
    /// Used to avoid redundant monomorphization at the cost of an extra branch or two.
    #[derive(Clone, Copy, Debug)]
    pub enum CompatibilityModeAsValue {
        Standard,
        LegacyY0AndAssociatedData,
    }

    /// The non-public parts of [`CompatibilityMode`].
    pub trait CompatibilityModeInternal {
        const ENUM: CompatibilityModeAsValue;
    }

    impl<T: CompatibilityModeInternal> CompatibilityMode for T {}
    impl CompatibilityModeInternal for LegacyMode {
        const ENUM: CompatibilityModeAsValue = CompatibilityModeAsValue::LegacyY0AndAssociatedData;
    }
    impl CompatibilityModeInternal for StandardMode {
        const ENUM: CompatibilityModeAsValue = CompatibilityModeAsValue::Standard;
    }
}
// A convenience export so the rest of the crate doesn't have to think about `sealed`.
pub(crate) use sealed::CompatibilityModeAsValue;

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
    /// Derives the correct `y0` value for a credential with `total_attr_count` attributes.
    ///
    /// Note that the `compatibility_mode` can revert this to a fixed value for any number of
    /// attributes.
    pub(crate) fn y0(
        &self,
        compatibility_mode: CompatibilityModeAsValue,
        total_attr_count: usize,
    ) -> Scalar {
        debug_assert!(
            (2..=NUM_SUPPORTED_ATTRS).contains(&total_attr_count),
            "credentials always have at least the public attribute slot and one more"
        );

        match compatibility_mode {
            CompatibilityModeAsValue::LegacyY0AndAssociatedData => self.y[0],
            CompatibilityModeAsValue::Standard => {
                if total_attr_count == 2 {
                    // This is purely a migration aid for one private key that *happened* to only be
                    // used with two-attr credentials.
                    self.y[0]
                } else {
                    let mut sho =
                        ShoHmacSha256::new(b"Signal_ZKCredential_SlotZeroBlinding_20260805");
                    sho.absorb_and_ratchet(&self.y[0].to_bytes());
                    sho.absorb_and_ratchet(&(total_attr_count as u64).to_be_bytes());
                    sho.get_scalar()
                }
            }
        }
    }

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
    ///
    /// `total_attr_count` is the arity of the credential as a whole, which selects the slot 0
    /// coefficient (see [`y0`](Self::y0)). It is *not* always `M.len()`: under blind issuance the
    /// server MACs only the cleartext attributes here and the blinded ones are folded in
    /// separately, but the arity that `I` is chosen for still counts both.
    pub(crate) fn credential_core(
        &self,
        M: &[RistrettoPoint],
        total_attr_count: usize,
        compatibility_mode: CompatibilityModeAsValue,
        sho: &mut dyn ShoApi,
    ) -> Credential {
        assert!(
            M.len() <= NUM_SUPPORTED_ATTRS,
            "more than {NUM_SUPPORTED_ATTRS} attributes not supported"
        );
        assert!(
            M.len() <= total_attr_count && total_attr_count <= NUM_SUPPORTED_ATTRS,
            "total attribute count must cover the attributes being signed"
        );
        let t = sho.get_scalar();
        let U = sho.get_point();

        let y0 = self.y0(compatibility_mode, total_attr_count);
        let mut V = self.W + (self.x0 + self.x1 * t) * U;
        for (i, (yn, Mn)) in self.y.iter().zip(M).enumerate() {
            let coefficient = if i == 0 { y0 } else { *yn };
            V += coefficient * Mn;
        }
        Credential { t, U, V }
    }

    /// Derives the appropriate public key for a key pair used under `compatibility_mode`.
    ///
    /// While the private key contents don't depend on the mode, and the way clients use the public
    /// key *also* doesn't depend on the mode, the way the *issuing server* and *verifying server*
    /// use the *public* key *does* depend on the mode, as do the contents of the public key itself.
    fn public_key(&self, compatibility_mode: CompatibilityModeAsValue) -> CredentialPublicKey {
        let system = *SYSTEM_PARAMS;

        let C_W = self.W + (self.wprime * system.G_wprime);
        // The running total deliberately excludes slot 0: its coefficient is domain-separated per
        // arity, so it has to be applied to each entry separately rather than accumulated once.
        let mut partial_I = system.G_V - (self.x0 * system.G_x0) - (self.x1 * system.G_x1);

        let mut y_and_G_y_iter = self.y.iter().zip(system.G_y).skip(1);
        let G_y0 = system.G_y[0];

        let mut total_attr_count = 1;
        let I = [(); NUM_SUPPORTED_ATTRS - 1].map(|_| {
            let (yn, G_yn) = y_and_G_y_iter.next().expect("correct number of parameters");
            partial_I -= yn * G_yn;
            total_attr_count += 1;
            let y0 = self.y0(compatibility_mode, total_attr_count);
            partial_I - (y0 * G_y0)
        });
        debug_assert!(y_and_G_y_iter.next().is_none());
        debug_assert_eq!(total_attr_count, NUM_SUPPORTED_ATTRS);

        CredentialPublicKey { C_W, I }
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

/// A key pair used by the issuing server to sign credentials.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Deserialize, PartialDefault)]
#[derive_where(Clone)]
#[serde(from = "CredentialPrivateKey", bound = "Mode: CompatibilityMode")]
#[partial_default(bound = "")]
pub struct CredentialKeyPair<Mode> {
    private_key: CredentialPrivateKey,
    public_key: CredentialPublicKey,
    mode: PhantomData<Mode>,
}

impl<Mode> CredentialKeyPair<Mode> {
    /// Generates a new key pair.
    pub fn generate(randomness: [u8; RANDOMNESS_LEN]) -> Self
    where
        Mode: CompatibilityMode,
    {
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

impl<Mode: CompatibilityMode> From<CredentialPrivateKey> for CredentialKeyPair<Mode> {
    fn from(private_key: CredentialPrivateKey) -> Self {
        let public_key = private_key.public_key(Mode::ENUM);
        Self {
            private_key,
            public_key,
            mode: PhantomData,
        }
    }
}

impl<Mode> Serialize for CredentialKeyPair<Mode> {
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
    use const_str::hex;
    use test_case::test_case;

    use super::*;

    impl SystemParams {
        const SYSTEM_HARDCODED: &'static [u8] = &hex!(
            "589c8718e8263a53a78932b6212a46e7fd52de3ad157b5bb277dba494cfd3471d4cc5f90685952917b33366efcce0512a1f8d70f974758266cb04fc424346d37b20f49cb2a081c94b1771fd8c172ae21785c61ea2c7e31947ce351e7b5ff07028c5329beb87b317ffcd981e440819d91136c988d6d9fbea4a87e55ed24a5993aa02f688ab1d3bd19056f94c8a44b8faddfa3c9c79c95ad44311a7bf00e5e862ec2c399f0d689dfb8c2dc0d7caba32afcf58cf0d85f78195a0b5ab732f565595492cfd982321d1f9be4b21fe6a0214306023d6a05d0d23f67ddc1c0400e5e0a5e92d17595131b7a095e740b884b8c9bb0226a39cfd027c769c4f4677c51f21b24da81fb2bd1356a9d0650f6a63fcc90d93bd74a954ba6f75f0e9fca47a6d21734bce7b28f06b76ef2c44d20a07026534e586eb8e1038874a93e44de362ce7bc0844bffc88e390c62519e281aa6fd53ff9ddd1d9ba303cf70004278ea2ae66ce05a2749d29eba56f3efe99e42902825c473dfc3c154c3762d2e76bd103f629d250b2d9d5c243a4cf8f3be21a84f153f44e2733a105cf780a20f03d84fe1ebbeb0e"
        );
    }

    #[test]
    fn test_system() {
        let params = SystemParams::generate();
        let serialized = bincode::serialize(&params).expect("can serialize");
        println!("PARAMS = {serialized:#x?}");
        assert!(serialized == SystemParams::SYSTEM_HARDCODED);
    }

    #[test_case(PhantomData::<StandardMode>)]
    #[test_case(PhantomData::<LegacyMode>)]
    fn round_trip_key_pair<T: CompatibilityMode>(_: PhantomData<T>) {
        let key_pair = CredentialKeyPair::<T>::generate([0x42; RANDOMNESS_LEN]);
        let serialized = bincode::serialize(&key_pair).unwrap();
        let deserialized: CredentialKeyPair<T> = bincode::deserialize(&serialized).unwrap();
        assert_eq!(&key_pair.public_key.C_W, &deserialized.public_key.C_W);
        assert_eq!(&key_pair.private_key.w, &deserialized.private_key.w);
    }
}
