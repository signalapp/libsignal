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

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use poksho::ShoApi;

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
pub trait PublicKey {
    /// A unique ID for this key (and its corresponding key pair)
    ///
    /// This is used to identify and distinguish keys when constructing or validating a proof,
    /// so make sure it's unique!
    fn id(&self) -> &'static str;
    /// The "generator points" for this key
    ///
    /// This can be a statically-chosen pair of points; it's used to construct [`A`](Self::A).
    fn G_a(&self) -> [RistrettoPoint; 2];
    /// The public key point, a commitment to the two scalars that make up the private key
    ///
    /// `A = a1 * G_a1 + a2 * G_a2`
    fn A(&self) -> RistrettoPoint;
}

/// A key used to encrypt attributes.
///
/// Using different keys for different attribute types prevents "type confusion", where two
/// attributes coincidentally have the same encoding as RistrettoPoints. The encryption may also
/// have other purposes, such as the encryption of UUIDs and profile keys in a Signal group, and
/// therefore being able to use existing keys is important.
///
/// Defined in Chase-Perrin-Zaverucha section 4.1.
///
/// See also [`PublicKey`].
pub trait KeyPair: PublicKey {
    /// The private key as a pair of scalars.
    ///
    /// Attributes are encrypted as `E_A1 = a1 * M1; E_A2 = a2 * E_A1 + M2`.
    fn a(&self) -> [Scalar; 2];
}

impl dyn KeyPair {
    /// Returns the second point from the plaintext that produced `ciphertext`
    ///
    /// The encryption form (described in [`KeyPair::a`]) allows recovering M2 from the ciphertext
    /// as `M2 = E_A2 - a2 * E_A1`. For certain attributes, this may be enough to recover the value,
    /// making this a reversible encryption system. However, it is **critical** to check that the
    /// decoded value produces the same `E_A1` when re-encrypted:
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
        ciphertext: &dyn Attribute,
    ) -> Result<RistrettoPoint, VerificationFailure> {
        let [E_A1, E_A2] = ciphertext.as_points();
        if E_A1 == RISTRETTO_BASEPOINT_POINT {
            return Err(VerificationFailure);
        }
        let [_, a2] = self.a();
        Ok(E_A2 - a2 * E_A1)
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
