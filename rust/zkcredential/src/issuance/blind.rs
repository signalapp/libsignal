//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Types used for issuing credentials over blinded attributes
//!
//! In addition to [normal issuance](crate::issuance), the client can also request a credential to
//! be issued over blinded attributes, which the issuing server cannot see. In this case, the
//! resulting credential and proof is encrypted with the same key used to blind attributes, and the
//! client must do a little extra work to decrypt it.
//!
//! With normal issuance, it's assumed that the attributes are chosen or at least validated by the
//! issuing server based on external knowledge; for example, an "AuthCredential" for a user's
//! account ID might be issued to a client that has used HTTP authentication to identify itself to
//! the issuing server. However, with blind issuance the server is by definition not able to
//! directly validate some of the attributes in the credential.
//!
//! Unless the credential can be issued over literally any value for a blinded attribute, the client
//! must provide a *request* proof that demonstrates why the blinded attributes are valid, i.e. why
//! the issuing server is authorized to issue the credential. For example, the
//! ProfileKeyCredentialRequest specified in section 5.9 of the Chase-Perrin-Zaverucha paper uses
//! the following statement:
//!
//! ```
//! let mut st = poksho::Statement::new();
//! // Common to every blinded issuance request proof.
//! st.add("Y", &[("y", "G")]);
//! st.add("D1", &[("r1", "G")]);
//! st.add("E1", &[("r2", "G")]); // one for each blinded point
//! // Specific to ProfileKeyCredentialRequest.
//! st.add("J3", &[("j3", "G_j3")]);
//! st.add("D2-J1", &[("r1", "Y"), ("j3", "-G_j1")]);
//! st.add("E2-J2", &[("r2", "Y"), ("j3", "-G_j2")]);
//! ```
//!
//! This statement involves the [`BlindingKeyPair`], [`BlindedAttribute`], and [`BlindedPoint`]
//! types in this module, but also additional points and scalars from a "commitment" that is assumed
//! to have been previously uploaded to the issuing server.
//!
//! In some cases, however, it *is* acceptable to issue a credential over "literally any value" for
//! a blinded attribute, usually when the value is some kind of randomly-generated or hash-derived
//! identifier. In this situation, it is acceptable to omit the request proof altogether, even
//! though it would still be possible to include the "common" statements; if the client does not
//! generate `Y` and `D1` according to the implementation shown here, they will not be able to
//! decode the resulting credential and have merely wasted everybody's time.
//!
//! You do not need to use [`BlindedIssuanceProofBuilder`] directly; start with a normal
//! [`IssuanceProofBuilder`] and use `add_blinded_attribute` to switch over to handling blinded
//! issuance proofs instead.
//!
//! Clients should use a new, one-off blinding key for every request.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use poksho::{ShoApi, ShoHmacSha256};
use serde::{Deserialize, Serialize};

use crate::attributes::{Attribute, RevealedAttribute};
use crate::credentials::{Credential, CredentialKeyPair, CredentialPublicKey, NUM_SUPPORTED_ATTRS};
use crate::issuance::IssuanceProofBuilder;
use crate::sho::ShoExt;
use crate::{VerificationFailure, RANDOMNESS_LEN};

#[cfg(doc)]
use crate::issuance::IssuanceProof;

/// Marker trait used by [`BlindedPoint`] and [`BlindedAttribute`].
///
/// See [`WithNonce`] and [`WithoutNonce`].
pub trait BlindedPointNonce {}

/// Wraps a nonce for [`BlindedPoint`] and [`BlindedAttribute`].
///
/// This explicitly does not support serde; once the nonce has been used to generate a request
/// proof, it should be discarded.
#[derive(Clone, Copy)]
pub struct WithNonce(pub Scalar);
impl BlindedPointNonce for WithNonce {}

/// Marks that a blinded point or attribute does not carry a nonce.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct WithoutNonce;
impl BlindedPointNonce for WithoutNonce {}

/// A representation of a single blinded point (part of a [`BlindedAttribute`])
///
/// Fully public so that other proofs can be made about blinded attributes. May or may not contain a
/// nonce, depending on `N`. The nonce can be discarded using the standard `From` trait.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct BlindedPoint<N: BlindedPointNonce = WithoutNonce> {
    /// Present only when `N` is [`WithNonce`].
    pub r: N,
    #[allow(missing_docs)]
    pub D1: RistrettoPoint,
    #[allow(missing_docs)]
    pub D2: RistrettoPoint,
}

impl From<BlindedPoint<WithNonce>> for BlindedPoint<WithoutNonce> {
    fn from(value: BlindedPoint<WithNonce>) -> Self {
        Self {
            r: WithoutNonce,
            D1: value.D1,
            D2: value.D2,
        }
    }
}

/// An attribute that has been blinded to the issuing server using a [`BlindingKeyPair`].
///
/// Fully public so that other proofs can be made about the attribute. May or may not contain a pair
/// of nonces, depending on `N`. The nonces can be discarded using the standard `From` trait.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct BlindedAttribute<N: BlindedPointNonce = WithoutNonce> {
    #[allow(missing_docs)]
    pub blinded_points: [BlindedPoint<N>; 2],
}

impl From<BlindedAttribute<WithNonce>> for BlindedAttribute<WithoutNonce> {
    fn from(value: BlindedAttribute<WithNonce>) -> Self {
        Self {
            blinded_points: value.blinded_points.map(Into::into),
        }
    }
}

/// A key used by the client to blind attributes to the issuing server.
///
/// Fully public so that other proofs can be made about blinded attributes.
#[derive(Serialize, Deserialize, Clone)]
pub struct BlindingPrivateKey {
    #[allow(missing_docs)]
    pub y: Scalar,
}

/// A key used by the issuing server to work with blinded attributes.
///
/// Fully public so that other proofs can be made about blinded attributes.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct BlindingPublicKey {
    #[allow(missing_docs)]
    pub Y: RistrettoPoint,
}

impl BlindingPrivateKey {
    /// Generates a new blinding key.
    fn generate(sho: &mut dyn ShoApi) -> Self {
        Self {
            y: sho.get_scalar(),
        }
    }
}

impl<'a> From<&'a BlindingPrivateKey> for BlindingPublicKey {
    fn from(private_key: &'a BlindingPrivateKey) -> Self {
        BlindingPublicKey {
            Y: private_key.y * RISTRETTO_BASEPOINT_POINT,
        }
    }
}

/// A key pair used by the client to blind attributes to the issuing server.
#[derive(Deserialize, Clone)]
#[serde(from = "BlindingPrivateKey")]
pub struct BlindingKeyPair {
    private_key: BlindingPrivateKey,
    public_key: BlindingPublicKey,
}

impl BlindingKeyPair {
    /// Generates a new blinding key pair.
    pub fn generate(sho: &mut dyn ShoApi) -> Self {
        BlindingPrivateKey::generate(sho).into()
    }

    /// Gets the private key.
    pub fn private_key(&self) -> &BlindingPrivateKey {
        &self.private_key
    }

    /// Gets the public key.
    pub fn public_key(&self) -> &BlindingPublicKey {
        &self.public_key
    }

    /// Blinds a revealed attribute for credential issuance.
    pub fn blind(
        &self,
        attr: &dyn RevealedAttribute,
        sho: &mut dyn ShoApi,
    ) -> BlindedPoint<WithNonce> {
        // This is technically something you can do with just the public key! But that would defeat
        // the purpose: if the issuing server encrypted additional attributes, it must already know
        // those attributes.
        let r = sho.get_scalar();
        let D1 = r * RISTRETTO_BASEPOINT_POINT;
        let D2 = r * self.public_key.Y + attr.as_point();
        BlindedPoint {
            r: WithNonce(r),
            D1,
            D2,
        }
    }

    /// Blinds an attribute for credential issuance.
    pub fn encrypt(
        &self,
        attr: &dyn Attribute,
        sho: &mut dyn ShoApi,
    ) -> BlindedAttribute<WithNonce> {
        // The points in a regular verifiably encrypted attribute aren't *really* "revealed
        // attributes", since they support homomorphic encryption for presentation.
        // But the implementation is the same.
        let attr_points = attr.as_points();
        BlindedAttribute {
            blinded_points: [
                self.blind(&attr_points[0], sho),
                self.blind(&attr_points[1], sho),
            ],
        }
    }
}

impl From<BlindingPrivateKey> for BlindingKeyPair {
    fn from(private_key: BlindingPrivateKey) -> Self {
        let public_key = BlindingPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

impl Serialize for BlindingKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.private_key.serialize(serializer)
    }
}

#[derive(Serialize, Deserialize)]
struct BlindedCredential {
    t: Scalar,
    U: RistrettoPoint,
    S1: RistrettoPoint,
    S2: RistrettoPoint,
}

/// Contains a [`Credential`] along with a proof of its validity.
///
/// Slightly larger than a typical [`IssuanceProof`] (which is why it's a separate type at all).
///
/// Use [`IssuanceProofBuilder`] to validate and extract the credential.
#[derive(Serialize, Deserialize)]
pub struct BlindedIssuanceProof {
    credential: BlindedCredential,
    poksho_proof: Vec<u8>,
}

/// A variant of [`IssuanceProofBuilder`] that handles blinded attributes.
///
/// `IssuanceProofBuilder` automatically switches over to one of these if you add blinded
/// attributes, and it processes [`BlindedIssuanceProof`] objects instead of plain
/// [`IssuanceProof`].
pub struct BlindedIssuanceProofBuilder<'a> {
    inner: IssuanceProofBuilder<'a>,
    blinded_attr_points: Vec<BlindedPoint<WithoutNonce>>,
}

impl BlindedIssuanceProofBuilder<'_> {
    /// Adds a blinded attribute to the credential.
    ///
    /// Blinded attributes must come after all other attributes, and are order-sensitive.
    pub fn add_blinded_attribute(self, attr: &BlindedAttribute<WithoutNonce>) -> Self {
        // The components of a blinded attribute aren't really "revealed" attributes,
        // but the implementation is the same.
        self.add_blinded_revealed_attribute(&attr.blinded_points[0])
            .add_blinded_revealed_attribute(&attr.blinded_points[1])
    }

    /// Adds a blinded "revealed" attribute to the credential.
    ///
    /// The attribute has been blinded for issuance, but will be revealed to the verifying server.
    ///
    /// Blinded point attributes must come after all other attributes, and are order-sensitive.
    pub fn add_blinded_revealed_attribute(mut self, attr: &BlindedPoint<WithoutNonce>) -> Self {
        self.blinded_attr_points.push(*attr);
        assert!(
            self.inner.attr_points.len() + self.blinded_attr_points.len() <= NUM_SUPPORTED_ATTRS,
            "more than {} hidden attribute points not supported",
            NUM_SUPPORTED_ATTRS - 1
        );
        self
    }

    fn get_poksho_statement(&self) -> poksho::Statement {
        // Generalized from Chase-Perrin-Zaverucha section 5.9.
        // n    = total number of attribute points
        // n_V' = number of unblinded attribute points
        let mut st = poksho::Statement::new();
        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);

        // G_V - I = x0 * G_x0 + x1 * G_x1 + sum(yi * G_yi, i = 0..n)
        let G_V_minus_I_terms: [_; NUM_SUPPORTED_ATTRS + 2] = [
            ("x0", "G_x0"),
            ("x1", "G_x1"),
            ("y0", "G_y0"),
            ("y1", "G_y1"),
            ("y2", "G_y2"),
            ("y3", "G_y3"),
            ("y4", "G_y4"),
            ("y5", "G_y5"),
            ("y6", "G_y6"),
        ];
        st.add(
            "G_V-I",
            &G_V_minus_I_terms[..2 + self.inner.attr_points.len() + self.blinded_attr_points.len()],
        );

        // S1 = r' * G + sum(yi * D1_i, i = n_V'..n)
        // We rely on the API guaranteeing that blinded attributes always come last.
        let S1_terms: [_; NUM_SUPPORTED_ATTRS] = [
            ("y0", "D1_0"),
            ("y1", "D1_1"),
            ("y2", "D1_2"),
            ("y3", "D1_3"),
            ("y4", "D1_4"),
            ("y5", "D1_5"),
            ("y6", "D1_6"),
        ];
        let mut S1 =
            S1_terms[self.inner.attr_points.len()..][..self.blinded_attr_points.len()].to_vec();
        S1.push(("rprime", "G"));
        st.add("S1", &S1);

        // V' = w * G_w + x0 * U + x1 * tU + sum(yi * Mi, i = 0..n_V')
        // S2 = rprime * Y + (V') + sum(yi * D2_i, i = n_V'..n)
        let V_terms_with_rprime: [_; NUM_SUPPORTED_ATTRS + 4] = [
            ("rprime", "Y"),
            ("w", "G_w"),
            ("x0", "U"),
            ("x1", "tU"),
            ("y0", "M0"),
            ("y1", "M1"),
            ("y2", "M2"),
            ("y3", "M3"),
            ("y4", "M4"),
            ("y5", "M5"),
            ("y6", "M6"),
        ];
        let S2_terms: [_; NUM_SUPPORTED_ATTRS] = [
            ("y0", "D2_0"),
            ("y1", "D2_1"),
            ("y2", "D2_2"),
            ("y3", "D2_3"),
            ("y4", "D2_4"),
            ("y5", "D2_5"),
            ("y6", "D2_6"),
        ];
        let mut S2 = V_terms_with_rprime[..4 + self.inner.attr_points.len()].to_vec();
        S2.extend(&S2_terms[self.inner.attr_points.len()..][..self.blinded_attr_points.len()]);
        st.add("S2", &S2);

        st
    }

    fn finalize_public_attrs(&mut self) {
        self.inner.finalize_public_attrs()
    }

    fn prepare_scalar_args(
        &self,
        key_pair: &CredentialKeyPair,
        rprime: Scalar,
    ) -> poksho::ScalarArgs {
        let mut scalar_args = self.inner.prepare_scalar_args(
            key_pair,
            self.inner.attr_points.len() + self.blinded_attr_points.len(),
        );
        scalar_args.add("rprime", rprime);
        scalar_args
    }

    fn prepare_point_args(
        &self,
        key: &CredentialPublicKey,
        blinding_key: &BlindingPublicKey,
        credential: &BlindedCredential,
    ) -> poksho::PointArgs {
        let mut point_args = self.inner.prepare_point_args(
            key,
            self.inner.attr_points.len() + self.blinded_attr_points.len(),
            None,
        );

        let point_names: [_; NUM_SUPPORTED_ATTRS] = [
            ("D1_0", "D2_0"),
            ("D1_1", "D2_1"),
            ("D1_2", "D2_2"),
            ("D1_3", "D2_3"),
            ("D1_4", "D2_4"),
            ("D1_5", "D2_5"),
            ("D1_6", "D2_6"),
        ];
        for ((d1_name, d2_name), point) in point_names
            .iter()
            .skip(self.inner.attr_points.len())
            .zip(&self.blinded_attr_points)
        {
            point_args.add(d1_name, point.D1);
            point_args.add(d2_name, point.D2);
        }

        point_args.add("S1", credential.S1);
        point_args.add("S2", credential.S2);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("Y", blinding_key.Y);

        point_args
    }

    /// Issues a new blinded credential over the accumulated attributes using the given `key_pair`
    /// and `blinding_key`.
    ///
    /// The blinding key is provided by the client to the issuing server; the corresponding private
    /// key will be used to decrypt the resulting credential.
    ///
    /// `randomness` ensures several important properties:
    /// - The generated credential is randomized (non-deterministic).
    /// - The credential is encrypted using a randomly generated key.
    /// - The issuance proof uses a random nonce.
    ///
    /// It is critical that different randomness is used each time a credential is issued. Failing
    /// to do so effectively reveals the server's private key.
    pub fn issue(
        mut self,
        key_pair: &CredentialKeyPair,
        blinding_key: &BlindingPublicKey,
        randomness: [u8; RANDOMNESS_LEN],
    ) -> BlindedIssuanceProof {
        self.finalize_public_attrs();

        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_BlindIssuance_20230410");
        sho.absorb_and_ratchet(&randomness);

        let rprime = sho.get_scalar();
        let S1 = rprime * RISTRETTO_BASEPOINT_POINT
            + key_pair
                .private_key()
                .y
                .iter()
                .skip(self.inner.attr_points.len())
                .zip(&self.blinded_attr_points)
                .map(|(yn, Dn)| yn * Dn.D1)
                .sum::<RistrettoPoint>();

        let base_credential = key_pair
            .private_key()
            .credential_core(&self.inner.attr_points, &mut sho);
        let S2 = rprime * blinding_key.Y
            + base_credential.V
            + key_pair
                .private_key()
                .y
                .iter()
                .skip(self.inner.attr_points.len())
                .zip(&self.blinded_attr_points)
                .map(|(yn, Dn)| yn * Dn.D2)
                .sum::<RistrettoPoint>();
        let credential = BlindedCredential {
            t: base_credential.t,
            U: base_credential.U,
            S1,
            S2,
        };

        let scalar_args = self.prepare_scalar_args(key_pair, rprime);
        let point_args = self.prepare_point_args(key_pair.public_key(), blinding_key, &credential);

        let poksho_proof = self
            .get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                self.inner.authenticated_message,
                &sho.squeeze_and_ratchet(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        BlindedIssuanceProof {
            poksho_proof,
            credential,
        }
    }

    /// Verifies the given `proof` over the accrued attributes using the given `public_key`
    /// and `blinding_key`.
    ///
    /// On successful verification, decrypts and returns the blinded credential that was just
    /// proven valid.
    pub fn verify(
        mut self,
        public_key: &CredentialPublicKey,
        blinding_key: &BlindingKeyPair,
        proof: BlindedIssuanceProof,
    ) -> Result<Credential, VerificationFailure> {
        self.finalize_public_attrs();
        let point_args =
            self.prepare_point_args(public_key, blinding_key.public_key(), &proof.credential);
        self.get_poksho_statement()
            .verify_proof(
                &proof.poksho_proof,
                &point_args,
                self.inner.authenticated_message,
            )
            .map_err(|_| VerificationFailure)?;
        let V = proof.credential.S2 - blinding_key.private_key().y * proof.credential.S1;
        Ok(Credential {
            t: proof.credential.t,
            U: proof.credential.U,
            V,
        })
    }
}

impl<'a> IssuanceProofBuilder<'a> {
    /// Adds a blinded attribute to the credential.
    ///
    /// This converts the builder to a [`BlindedIssuanceProofBuilder`]. Blinded attributes must come
    /// after all other attributes, and are order-sensitive.
    pub fn add_blinded_attribute(
        self,
        attr: &BlindedAttribute<WithoutNonce>,
    ) -> BlindedIssuanceProofBuilder<'a> {
        BlindedIssuanceProofBuilder {
            inner: self,
            blinded_attr_points: vec![],
        }
        .add_blinded_attribute(attr)
    }

    /// Adds a blinded "revealed" attribute to the credential.
    ///
    /// The attribute has been blinded for issuance, but will be revealed to the verifying server.
    ///
    /// This converts the builder to a [`BlindedIssuanceProofBuilder`]. Blinded attributes must come
    /// after all other attributes, and are order-sensitive.
    pub fn add_blinded_revealed_attribute(
        self,
        attr: &BlindedPoint<WithoutNonce>,
    ) -> BlindedIssuanceProofBuilder<'a> {
        BlindedIssuanceProofBuilder {
            inner: self,
            blinded_attr_points: vec![],
        }
        .add_blinded_revealed_attribute(attr)
    }
}

#[test]
fn round_trip_key_pair() {
    let key_pair = BlindingKeyPair::generate(&mut poksho::ShoSha256::new(b"test"));
    let serialized = bincode::serialize(&key_pair).unwrap();
    let deserialized: BlindingKeyPair = bincode::deserialize(&serialized).unwrap();
    assert_eq!(&key_pair.public_key.Y, &deserialized.public_key.Y);
    assert_eq!(&key_pair.private_key.y, &deserialized.private_key.y);
}
