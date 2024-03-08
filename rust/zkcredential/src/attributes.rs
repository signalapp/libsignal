//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Traits used for the attributes in a credential.
//!
//! Your attribute types must implement one of these traits. There are three kinds of supported
//! attributes:
//! - [`PublicAttribute`], which does not need to be hidden from the issuing server or verifying
//!   server.
//! - [`Attribute`] (the reason for this entire credential system), which is hidden from the
//!   verifying server using verifiable encryption, and may be hidden from the issuing server as
//!   well with [blind issuance](crate::issuance::blind).
//! - [`RevealedAttribute`], which is hidden from the issuing server and then revealed to the
//!   verifying server.

use std::marker::PhantomData;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use derive_where::derive_where;
use partial_default::PartialDefault;
use poksho::ShoApi;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::sho::ShoExt;
use crate::VerificationFailure;

/// An attribute that doesn't need to be hidden from the issuing server or verifying server.
///
/// This can be encoded more efficiently, making for smaller, faster proofs.
/// (All public attributes get hashed together along with the credential type.)
pub trait PublicAttribute {
    /// Mixes `self` into the hash computed by `sho`.
    ///
    /// This will usually be implemented by calling [`ShoApi::absorb_and_ratchet`] one or more
    /// times.
    fn hash_into(&self, sho: &mut dyn ShoApi);
}

impl PublicAttribute for [u8] {
    fn hash_into(&self, sho: &mut dyn ShoApi) {
        sho.absorb_and_ratchet(self)
    }
}

impl<const LEN: usize> PublicAttribute for [u8; LEN] {
    fn hash_into(&self, sho: &mut dyn ShoApi) {
        self.as_slice().hash_into(sho)
    }
}

impl PublicAttribute for u32 {
    fn hash_into(&self, sho: &mut dyn ShoApi) {
        self.to_be_bytes().hash_into(sho)
    }
}

impl PublicAttribute for u64 {
    fn hash_into(&self, sho: &mut dyn ShoApi) {
        self.to_be_bytes().hash_into(sho)
    }
}

/// An attribute representable as a pair of [`RistrettoPoint`s](RistrettoPoint).
///
/// Used for credential attributes that need to take advantage of homomorphic encryption. Attributes
/// that never need to be hidden should use [`PublicAttribute`] instead. Attributes that only need
/// to be hidden during issuance may use the more compact [`RevealedAttribute`] instead.
///
/// For an attribute that is encrypted, both the attribute type and its corresponding ciphertext
/// type should conform to this trait. Note that blinded attributes do not conform to this trait, as
/// they have a different representation.
pub trait Attribute {
    /// Converts `self` into a pair of points.
    ///
    /// It is strongly recommended for an attribute's non-encrypted form that you generate the first
    /// point by hashing and use the second to encode your encrypted information.
    ///
    /// The encrypted attribute should apply [`KeyPair`]'s encryption to the point.
    fn as_points(&self) -> [RistrettoPoint; 2];
}

impl Attribute for [RistrettoPoint; 2] {
    fn as_points(&self) -> [RistrettoPoint; 2] {
        *self
    }
}

/// A domain for a [`KeyPair`].
///
/// This provides separation between different keys and ciphertexts, so that statically and
/// dynamically they can't get mixed up or substituted for one another.
///
/// # Example
///
/// ```
/// # use curve25519_dalek::RistrettoPoint;
/// # type UserId = [RistrettoPoint; 2];
/// struct UserIdEncryption;
/// impl zkcredential::attributes::Domain for UserIdEncryption {
///   type Attribute = UserId;
///   const ID: &'static str = "MyCompany_UserIdEncryption_20231011";
///
///   fn G_a() -> [RistrettoPoint; 2] {
///     static STORAGE: std::sync::OnceLock<[RistrettoPoint; 2]> = std::sync::OnceLock::new();
///     *zkcredential::attributes::derive_default_generator_points::<Self>(&STORAGE)
///   }
/// }
/// ```
pub trait Domain {
    /// The attribute type used in this encryption domain.
    type Attribute: Attribute;

    /// A unique ID for this key (and its corresponding key pair)
    ///
    /// This is used to identify and distinguish keys when constructing or validating a proof,
    /// so make sure it's unique!
    const ID: &'static str;

    /// The "generator points" for this key
    ///
    /// This can be a statically-chosen pair of points; it's used to construct the `A` point for a
    /// [`PublicKey`].
    ///
    /// A reasonable default implementation would use `derive_default_generator_points` with static
    /// storage, for caching the resulting points:
    ///
    /// ```
    /// # use curve25519_dalek::RistrettoPoint;
    /// # struct Example;
    /// # impl zkcredential::attributes::Domain for Example {
    /// #   type Attribute = [RistrettoPoint; 2];
    /// #   const ID: &'static str = "20231030_Example";
    /// fn G_a() -> [RistrettoPoint; 2] {
    ///   static STORAGE: std::sync::OnceLock<[RistrettoPoint; 2]> = std::sync::OnceLock::new();
    ///   *zkcredential::attributes::derive_default_generator_points::<Self>(&STORAGE)
    /// }
    /// # }
    /// ```
    ///
    /// Unfortunately this can't be provided as a default implementation, because that would result
    /// in every domain sharing the same `STORAGE`, as if it were declared outside the trait.
    fn G_a() -> [RistrettoPoint; 2];
}

/// Derives reasonable generator points `G_a` for `D`, based on its [`ID`][Domain::ID], and caches
/// them in `storage`.
pub fn derive_default_generator_points<D: Domain>(
    storage: &std::sync::OnceLock<[RistrettoPoint; 2]>,
) -> &[RistrettoPoint; 2] {
    fn derive_impl<D: Domain>() -> [RistrettoPoint; 2] {
        let mut sho = poksho::ShoHmacSha256::new(b"Signal_ZKCredential_Domain_20231011");
        sho.absorb_and_ratchet(D::ID.as_bytes());
        let G_a1 = sho.get_point();
        let G_a2 = sho.get_point();
        [G_a1, G_a2]
    }

    let result = storage.get_or_init(derive_impl::<D>);
    debug_assert!(
        result == &derive_impl::<D>(),
        "initialized with non-default points for {}",
        D::ID,
    );
    result
}

/// A key used to encrypt attributes.
///
/// Using different keys for different attribute types prevents "type confusion", where two
/// attributes coincidentally have the same encoding as RistrettoPoints. The encryption may also
/// have other purposes, such as the encryption of UUIDs and profile keys in a Signal group, and
/// therefore being able to use existing keys is important.
///
/// The private key in this system is a pair of scalars `a1` and `a2`. Attributes are encrypted as
/// `E_A1 = a1 * M1; E_A2 = a2 * E_A1 + M2`.
///
/// Defined in Chase-Perrin-Zaverucha section 4.1.
///
/// See also [`PublicKey`].
#[derive(Serialize, Deserialize, PartialDefault)]
#[derive_where(Clone, Copy, Eq)]
#[partial_default(bound = "")]
#[non_exhaustive]
#[allow(missing_docs)]
pub struct KeyPair<D> {
    pub a1: Scalar,
    pub a2: Scalar,
    #[serde(bound = "")]
    pub public_key: PublicKey<D>,
}

impl<D> subtle::ConstantTimeEq for KeyPair<D> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.a1.ct_eq(&other.a1) & self.a2.ct_eq(&other.a2)
    }
}
impl<D> PartialEq for KeyPair<D> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// A key used to validate encrypted attributes.
///
/// Using different keys for different attribute types prevents "type confusion", where two
/// attributes coincidentally have the same encoding as RistrettoPoints. The encryption may also
/// have other purposes, such as the encryption of UUIDs and profile keys in a Signal group, and
/// therefore being able to use existing keys is important.
///
/// Defined in Chase-Perrin-Zaverucha section 4.1.
///
/// See also [`KeyPair`].
#[derive(Serialize, Deserialize, PartialDefault)]
#[derive_where(Clone, Copy, Eq)]
#[partial_default(bound = "")]
pub struct PublicKey<D> {
    #[allow(missing_docs)]
    pub A: RistrettoPoint,
    #[serde(skip)]
    domain: PhantomData<fn(D) -> D>,
}

impl<D> subtle::ConstantTimeEq for PublicKey<D> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.A.ct_eq(&other.A)
    }
}
impl<D> PartialEq for PublicKey<D> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<D: Domain> KeyPair<D> {
    /// Generates a new KeyPair from the hash state in `sho`.
    ///
    /// Passing the same `sho` state in will produce the same key pair every time.
    pub fn derive_from(sho: &mut dyn ShoApi) -> Self {
        let a1 = sho.get_scalar();
        let a2 = sho.get_scalar();

        Self::from_scalars(a1, a2)
    }

    fn from_scalars(a1: Scalar, a2: Scalar) -> Self {
        let [G_a1, G_a2] = D::G_a();
        let A = a1 * G_a1 + a2 * G_a2;

        Self {
            a1,
            a2,
            public_key: PublicKey {
                A,
                domain: PhantomData,
            },
        }
    }

    /// Creates a KeyPair that's the inverse of `other`.
    ///
    /// That is, if `k_inv` is `KeyPair::inverse_of(k)`, then `attr.as_points() ==
    /// k_inv.encrypt(k.encrypt(&attr))`.
    ///
    /// Note that the domain of `Self` doesn't have to be related to the domain of `other`. This can
    /// be useful when the inverted key is used on derived values.
    ///
    /// Don't use this to decrypt points; there are more efficient ways to do that. See
    /// [`Self::decrypt_to_second_point`].
    pub fn inverse_of<D2: Domain>(other: &KeyPair<D2>) -> Self {
        assert_ne!(
            D::ID,
            D2::ID,
            "You must provide a new domain for an inverse key"
        );
        let a1 = other.a1.invert();
        let a2 = -(other.a1 * other.a2);
        Self::from_scalars(a1, a2)
    }

    /// Encrypts `attr` according to Chase-Perrin-Zaverucha section 4.1.
    #[inline]
    pub fn encrypt(&self, attr: &D::Attribute) -> Ciphertext<D> {
        self.encrypt_arbitrary_attribute(attr)
    }

    /// Encrypts `attr` according to Chase-Perrin-Zaverucha section 4.1, even if the attribute is
    /// not normally associated with this key.
    ///
    /// Allows controlling the domain of the resulting ciphertext, to not get confused with the
    /// usual ciphertexts produced by [`Self::encrypt`].
    #[inline]
    pub fn encrypt_arbitrary_attribute<D2>(&self, attr: &dyn Attribute) -> Ciphertext<D2> {
        let [M1, M2] = attr.as_points();
        let E_A1 = self.a1 * M1;
        let E_A2 = (self.a2 * E_A1) + M2;
        Ciphertext {
            E_A1,
            E_A2,
            domain: PhantomData,
        }
    }

    /// Returns the second point from the plaintext that produced `ciphertext`
    ///
    /// The encryption form allows recovering M2 from the ciphertext as `M2 = E_A2 - a2 * E_A1`. For
    /// certain attributes, this may be enough to recover the value, making this a reversible
    /// encryption system. However, it is **critical** to check that the decoded value produces the
    /// same `E_A1` when re-encrypted:
    ///
    /// ```ignored
    /// a1 * HashToPoint(DecodeFromPoint(M2)) == E_A1
    /// ```
    ///
    /// This addresses the fact that this method is otherwise "garbage in, garbage out": it will
    /// "decrypt" *any* ciphertext passed to it regardless of whether or not that ciphertext came
    /// from a valid plaintext, encrypted using the same key.
    ///
    /// Produces an error if `E_A1` is the Ristretto basepoint, which would imply that `a1` is not
    /// actually encrypting anything.
    ///
    /// Defined in Chase-Perrin-Zaverucha section 3.1.
    pub fn decrypt_to_second_point(
        &self,
        ciphertext: &Ciphertext<D>,
    ) -> Result<RistrettoPoint, VerificationFailure> {
        if ciphertext.E_A1 == RISTRETTO_BASEPOINT_POINT {
            return Err(VerificationFailure);
        }
        Ok(ciphertext.E_A2 - self.a2 * ciphertext.E_A1)
    }
}

/// An attribute encrypted with [`KeyPair::encrypt`].
#[derive(Serialize, Deserialize, PartialDefault)]
#[derive_where(Clone, Copy, Eq)]
#[partial_default(bound = "")]
pub struct Ciphertext<D> {
    E_A1: RistrettoPoint,
    E_A2: RistrettoPoint,
    #[serde(skip)]
    domain: PhantomData<fn(D) -> D>,
}

impl<D> subtle::ConstantTimeEq for Ciphertext<D> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.E_A1.ct_eq(&other.E_A1) & self.E_A2.ct_eq(&other.E_A2)
    }
}

impl<D> PartialEq for Ciphertext<D> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<D> Attribute for Ciphertext<D> {
    #[inline]
    fn as_points(&self) -> [RistrettoPoint; 2] {
        [self.E_A1, self.E_A2]
    }
}

/// An attribute that is [blinded](crate::issuance::blind) to the issuing server but revealed to the
/// verifying server.
///
/// Used only in the very specific case described above. Attributes that never need to be hidden
/// should use [`PublicAttribute`] instead; attributes that need to be hidden from the verifying
/// server should use the standard [`Attribute`].
///
/// This scenario does not appear in the Chase-Perrin-Zaverucha paper, but is a simplified version
/// of the blind issuance protocol shown in section 5.9.
pub trait RevealedAttribute {
    /// Converts `self` to a point.
    ///
    /// It is strongly recommended you do this by hashing unless you have a specific reason to do
    /// otherwise.
    fn as_point(&self) -> RistrettoPoint;
}

impl RevealedAttribute for RistrettoPoint {
    fn as_point(&self) -> RistrettoPoint {
        *self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    struct ExampleDomain;
    impl Domain for ExampleDomain {
        type Attribute = [RistrettoPoint; 2];
        const ID: &'static str = "TestDomain";

        fn G_a() -> [RistrettoPoint; 2] {
            static STORAGE: OnceLock<[RistrettoPoint; 2]> = OnceLock::new();
            *derive_default_generator_points::<Self>(&STORAGE)
        }
    }

    #[test]
    fn derive_default_generator_points_works() {
        let _ = ExampleDomain::G_a();
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)]
    fn derive_default_generator_points_checks_for_reuse_in_debug_builds() {
        let storage = std::sync::OnceLock::from([RistrettoPoint::default(); 2]);
        derive_default_generator_points::<ExampleDomain>(&storage);
    }
}
