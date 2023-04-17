//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The generation and verification of credential presentation proofs
//!
//! When the client wishes to use a credential, it generates a _presentation proof_ over the same
//! attributes that went into the original credential. This allows the client to demonstrate that
//! they hold a credential over certain attributes without actually revealing those attributes. The
//! verifying server will verify the proof against the encrypted forms of those attributes and is
//! thus assured that the client does hold a credential from the issuing server.
//!
//! By providing the same attributes in the same order, a proof can be generated and verified with
//! parallel invocations. The size of the proof scales linearly with the number of attributes.
//!
//! It is recommended that the client generate a new presentation for every use of their private
//! credential, so that the verifying server cannot track repeated uses of the same presentation. Of
//! course, the encrypted forms of the attributes might also allow the verifying server to correlate
//! requests over time.
//!
//! Credential presentation is defined in Chase-Perrin-Zaverucha section 3.2; proofs for verifiable
//! encryption are defined in section 4.1.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use poksho::{ShoApi, ShoHmacSha256};
use serde::{Deserialize, Serialize};

use crate::attributes::{self, Attribute, PublicAttribute, RevealedAttribute};
use crate::credentials::{
    Credential, CredentialKeyPair, CredentialPrivateKey, CredentialPublicKey, SystemParams,
    NUM_SUPPORTED_ATTRS,
};
use crate::sho::ShoExt;
use crate::{VerificationFailure, RANDOMNESS_LEN};

#[derive(Serialize, Deserialize)]
struct PresentationProofCommitments {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_V: RistrettoPoint,
    C_y: Vec<RistrettoPoint>,
}

/// Demonstrates to the _verifying server_ that the client holds a particular credential.
///
/// Use [`PresentationProofVerifier`] to validate the proof.
#[derive(Serialize, Deserialize)]
pub struct PresentationProof {
    commitments: PresentationProofCommitments,
    poksho_proof: Vec<u8>,
}

struct AttributeRef {
    key_index: Option<usize>,
    first_point_index: usize,
    second_point_index: usize,
}

struct PresentationProofBuilderCore<'a, T: attributes::PublicKey + ?Sized> {
    encryption_keys: Vec<&'a T>,
    attributes: Vec<AttributeRef>,
    attr_points: Vec<RistrettoPoint>,
    authenticated_message: &'a [u8],
}

/// Used to generate presentation proofs.
///
/// Public attributes are not included from the presentation proof; when the proof is verified, the
/// verifying server will provide its own copy of the public attributes to ensure that they haven't
/// been tampered with.
///
/// See also [`PresentationProofVerifier`].
pub struct PresentationProofBuilder<'a> {
    core: PresentationProofBuilderCore<'a, dyn attributes::KeyPair + 'a>,
}

/// Used to verify presentation proofs.
///
/// By providing the same attributes in the same order, a proof can be generated and verified with
/// parallel invocations. The size of the proof scales linearly with the number of attributes.
///
/// Public attributes are not included from the presentation proof; when the proof is verified, the
/// verifying server will provide its own copy of the public attributes to ensure that they haven't
/// been tampered with, as mentioned in Chase-Perrin-Zaverucha section 3.2.
///
/// See also [`PresentationProofBuilder`].
pub struct PresentationProofVerifier<'a> {
    core: PresentationProofBuilderCore<'a, dyn attributes::PublicKey + 'a>,
    public_attrs: ShoHmacSha256,
}

impl<'a, T: attributes::PublicKey + ?Sized> PresentationProofBuilderCore<'a, T> {
    fn with_authenticated_message(message: &'a [u8]) -> Self {
        Self {
            encryption_keys: vec![],
            attributes: vec![],
            // Reserve the first point for public attributes
            attr_points: vec![RistrettoPoint::identity()],
            authenticated_message: message,
        }
    }

    fn add_attribute(&mut self, attr_points: &[RistrettoPoint], key: Option<&'a T>) {
        let first_index = self.attr_points.len();
        self.attr_points.extend(attr_points);
        assert!(
            self.attr_points.len() <= NUM_SUPPORTED_ATTRS,
            "more than {} hidden attribute points not supported",
            NUM_SUPPORTED_ATTRS - 1
        );

        let key_index = key.map(|key| {
            let key_id = key.id();
            match self
                .encryption_keys
                .iter()
                .position(|key| key.id() == key_id)
            {
                Some(idx) => idx,
                None => {
                    let idx = self.encryption_keys.len();
                    self.encryption_keys.push(key);
                    idx
                }
            }
        });

        // If we ever support attributes longer than two points we'll have to change this.
        self.attributes.push(AttributeRef {
            key_index,
            first_point_index: first_index,
            second_point_index: first_index + attr_points.len() - 1,
        });
    }

    fn get_poksho_statement(&self) -> poksho::Statement {
        let mut st = poksho::Statement::new();
        // These terms are from Chase-Perrin-Zaverucha section 3.2.
        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);

        // These terms are from Chase-Perrin-Zaverucha section 4.1,
        // proving the validity of the encryption keys.
        let mut encryption_sum_terms = vec![];
        for key in &self.encryption_keys {
            let key = key.id();
            let a1 = format!("a1_{}", key);

            // These terms are an addition by Trevor Perrin to the original paper to more carefully
            // ensure the validity of the encryption keys used.
            // 0 = z1_uid * I + a1_uid * Z
            st.add("0", &[(&format!("z1_{}", key), "I"), (&a1, "Z")]);

            encryption_sum_terms.push((a1, format!("G_a1_{}", key)));
            encryption_sum_terms.push((format!("a2_{}", key), format!("G_a2_{}", key)));
        }
        if !self.encryption_keys.is_empty() {
            // sum(A) = (a1_uid * G_a1_uid) + (a2_uid * G_a2_uid) +
            //          (a1_profilekey * G_a1_profilekey) + (a2_profilekey * G_a2_profilekey) +
            //          ...
            st.add(
                "sum(A)",
                &encryption_sum_terms
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect::<Vec<_>>(),
            );
        }

        for attr in &self.attributes {
            if let Some(key_index) = attr.key_index {
                // If this attribute uses a key, it's a verifiably encrypted Attribute.
                // These terms are from Chase-Perrin-Zaverucha section 4.1,
                // proving that the ciphertext matches the attribute in the credential.
                let key_id = self.encryption_keys[key_index].id();
                // E_A1 = a1_uid * C_y1 + z1_uid * G_y1
                st.add(
                    &format!("E_A{}", attr.first_point_index),
                    &[
                        (
                            &format!("a1_{}", key_id),
                            &format!("C_y{}", attr.first_point_index),
                        ),
                        (
                            &format!("z1_{}", key_id),
                            &format!("G_y{}", attr.first_point_index),
                        ),
                    ],
                );
                // C_y2 - E_A2 = z * G_y2 + a2_uid * -E_A1
                st.add(
                    &format!("C_y{0}-E_A{0}", attr.second_point_index),
                    &[
                        ("z", &format!("G_y{}", attr.second_point_index)),
                        (
                            &format!("a2_{}", key_id),
                            &format!("-E_A{}", attr.first_point_index),
                        ),
                    ],
                );
            } else {
                // If the attribute does not use a key, it's a RevealedAttribute.
                // (We don't currently support hidden scalar attributes.)
                // This is from section 3.2 again; C_y1 is otherwise unbound.
                debug_assert_eq!(attr.first_point_index, attr.second_point_index);
                // C_y1 = z * G_y1
                st.add(
                    &format!("C_y{}", attr.first_point_index),
                    &[("z", &format!("G_y{}", attr.first_point_index))],
                );
            }
        }

        // Point 0 is a hardcoded public attribute.
        st.add("C_y0", &[("z", "G_y0")]);

        st
    }

    /// Generates [`poksho::PointArgs`] containing all points not derived from attributes.
    ///
    /// This includes the credential key commitments `C_x0`, `C_x1`, and `C_y0`; the system points
    /// `G_x0`, `G_x1`, and all `G_y{i}`; the appropriate issuing parameter point `I`; and the
    /// points necessary to prove the validity of encryption keys: `0`, `G_a1_{key}`, `G_a2_{key}`,
    /// and `sum(A)`.
    ///
    /// The caller is responsible for handling the presenter's one-off public point `Z` (which the
    /// verifier derives from the commitments and public attributes); the appropriate `C_y{i}` for
    /// all attributes besides public attributes (depending on whether or not attributes are
    /// encrypted); and the encryption-specific points `E_A{i}`, `-E_A{i}`, and `C_y{j}-E_A{j}`.
    fn prepare_non_attribute_point_args(
        &self,
        I: RistrettoPoint,
        commitments: &PresentationProofCommitments,
    ) -> poksho::PointArgs {
        let credentials_system = SystemParams::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();
        point_args.add("I", I);

        point_args.add("C_x0", commitments.C_x0);
        point_args.add("C_x1", commitments.C_x1);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);

        if !self.encryption_keys.is_empty() {
            point_args.add("0", RistrettoPoint::identity());
            let mut sum_A = RistrettoPoint::identity();
            for key in &self.encryption_keys {
                let [G_a1, G_a2] = key.G_a();
                point_args.add(&format!("G_a1_{}", key.id()), G_a1);
                point_args.add(&format!("G_a2_{}", key.id()), G_a2);
                sum_A += key.A();
            }
            point_args.add("sum(A)", sum_A);
        }

        let G_y_names: [_; NUM_SUPPORTED_ATTRS] =
            ["G_y0", "G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6"];
        for (G_y_name, G_yn) in G_y_names
            .iter()
            .take(self.attr_points.len())
            .zip(credentials_system.G_y)
        {
            point_args.add(G_y_name, G_yn)
        }

        point_args.add("C_y0", commitments.C_y[0]);
        // Other C_y depend on the form of the attribute.

        point_args
    }
}

impl<'a> PresentationProofBuilder<'a> {
    /// Initializes a new proof builder.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential, but as
    /// a public attribute it is ignored. It is merely here for symmetry with
    /// [`PresentationProofVerifier::new`].
    pub fn new(label: &[u8]) -> Self {
        Self::with_authenticated_message(label, &[])
    }

    /// Initializes a new proof builder.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential, but as
    /// a public attribute it is ignored. It is merely here for symmetry with
    /// [`PresentationProofVerifier::with_authenticated_message`].
    ///
    /// `message`, however, is not an attribute and is not part of the original credential; it is
    /// merely part of the proof. This could, for example, be used to distinguish multiple proofs
    /// that present the same kind of credential.
    pub fn with_authenticated_message(label: &[u8], message: &'a [u8]) -> Self {
        _ = label;
        Self {
            core: PresentationProofBuilderCore::with_authenticated_message(message),
        }
    }

    /// Unnecessary: public attributes are passed directly to the verifying server.
    #[deprecated = "Unnecessary: public attributes are passed directly to the verifying server."]
    pub fn add_public_attribute(self, attr: &dyn PublicAttribute) -> Self {
        _ = attr;
        self
    }

    /// Adds an attribute to the proof, which will be encrypted using `key`.
    ///
    /// This is order-sensitive.
    pub fn add_attribute(mut self, attr: &dyn Attribute, key: &'a dyn attributes::KeyPair) -> Self {
        self.core.add_attribute(&attr.as_points(), Some(key));
        self
    }

    /// Adds an attribute to check against the credential.
    ///
    /// In practice `attr` is ignored in favor of letting the verifying server check the attribute
    /// itself, but it's still necessary to call this method to indicate that there *is* an
    /// attribute.
    ///
    /// This is order-sensitive.
    pub fn add_revealed_attribute(mut self, attr: &dyn RevealedAttribute) -> Self {
        // We don't actually need the value! The server will check it for us.
        _ = attr;
        self.core.add_attribute(&[RistrettoPoint::identity()], None);
        self
    }

    /// Generates the presentation of `credential` using the server-provided `public_key`.
    ///
    /// Note that this does not consume `credential`; indeed, it is recommended to use a new
    /// presentation every time you want to use a particular credential.
    ///
    /// `randomness` ensures several important properties:
    /// - The generated presentation is randomized (non-deterministic).
    /// - The presentation proof uses a random nonce.
    ///
    /// It is critical that different randomness is used each time a credential is issued. Failing
    /// to do so allows different presentations to be linked to the same credential (and thus the
    /// same user), and worse, effectively reveals any hidden Attributes and their encryption keys.
    pub fn present(
        self,
        public_key: &CredentialPublicKey,
        credential: &Credential,
        randomness: [u8; RANDOMNESS_LEN],
    ) -> PresentationProof {
        let credentials_system = SystemParams::get_hardcoded();

        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_Presentation_20230410");
        sho.absorb_and_ratchet(&randomness);
        let z = sho.get_scalar();

        debug_assert!(
            self.core.attr_points[0] == RistrettoPoint::identity(),
            "public attributes are incorporated by the server"
        );
        // Note that Mn will be the identity element for both the first point and for any
        // RevealedAttributes, so this will simply produce `z * G_yn` for those elements as in
        // Chase-Perrin-Zaverucha section 3.2.
        let C_y = credentials_system
            .G_y
            .iter()
            .zip(&self.core.attr_points)
            .map(|(G_yn, Mn)| z * G_yn + Mn)
            .collect::<Vec<_>>();

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;

        let commitments = PresentationProofCommitments {
            C_x0,
            C_x1,
            C_V,
            C_y,
        };

        let z0 = -z * credential.t;

        let I = public_key.I(self.core.attr_points.len());
        let Z = z * I;

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        for key in &self.core.encryption_keys {
            let [a1, a2] = key.a();
            scalar_args.add(&format!("a1_{}", key.id()), a1);
            scalar_args.add(&format!("a2_{}", key.id()), a2);
            scalar_args.add(&format!("z1_{}", key.id()), -z * a1);
        }

        let mut point_args = self.core.prepare_non_attribute_point_args(I, &commitments);
        point_args.add("Z", Z);
        for attr in &self.core.attributes {
            let &AttributeRef {
                key_index,
                first_point_index,
                second_point_index,
            } = attr;
            point_args.add(
                &format!("C_y{}", first_point_index),
                commitments.C_y[first_point_index],
            );

            if let Some(key_index) = key_index {
                let key = self.core.encryption_keys[key_index];
                let [a1, a2] = key.a();
                let E_A1 = a1 * self.core.attr_points[first_point_index];
                let E_A2 = a2 * E_A1 + self.core.attr_points[second_point_index];
                point_args.add(&format!("E_A{}", first_point_index), E_A1);
                point_args.add(&format!("-E_A{}", first_point_index), -E_A1);
                point_args.add(
                    &format!("C_y{0}-E_A{0}", second_point_index),
                    commitments.C_y[second_point_index] - E_A2,
                );
            } else {
                debug_assert!(
                    self.core.attr_points[first_point_index] == RistrettoPoint::identity(),
                    "revealed attributes are incorporated by the server"
                );
            }
        }

        let poksho_proof = self
            .core
            .get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                self.core.authenticated_message,
                &sho.squeeze_and_ratchet(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        PresentationProof {
            commitments,
            poksho_proof,
        }
    }
}

impl<'a> PresentationProofVerifier<'a> {
    /// Initializes a new proof verifier.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    pub fn new(label: &[u8]) -> Self {
        Self::with_authenticated_message(label, &[])
    }

    /// Initializes a new proof verifier.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    /// `message`, however, is not an attribute and is not part of the original credential; it is
    /// merely part of the proof. This could, for example, be used to distinguish multiple proofs
    /// that present the same kind of credential.
    pub fn with_authenticated_message(label: &[u8], message: &'a [u8]) -> Self {
        Self {
            core: PresentationProofBuilderCore::with_authenticated_message(message),
            public_attrs: ShoHmacSha256::new(label),
        }
    }

    /// Adds a public attribute to check against the credential.
    ///
    /// This is order-sensitive.
    pub fn add_public_attribute(mut self, attr: &dyn PublicAttribute) -> Self {
        attr.hash_into(&mut self.public_attrs);
        self.public_attrs.ratchet();
        self
    }

    /// Adds an encrypted attribute to check against the credential, along with the public key for
    /// the key it was encrypted with.
    ///
    /// This is order-sensitive.
    pub fn add_attribute(
        mut self,
        attr: &dyn Attribute,
        key: &'a dyn attributes::PublicKey,
    ) -> Self {
        self.core.add_attribute(&attr.as_points(), Some(key));
        self
    }

    /// Adds an attribute to check against the credential, unencrypted.
    ///
    /// This should only be used when the attribute is blinded from the issuing server, but visible
    /// to the verifying server. Use public attributes when the value doesn't need to be hidden at
    /// all.
    ///
    /// This is order-sensitive.
    pub fn add_revealed_attribute(mut self, attr: &dyn RevealedAttribute) -> Self {
        self.core.add_attribute(&[attr.as_point()], None);
        self
    }

    fn finalize_public_attrs(&mut self) {
        debug_assert!(self.core.attr_points[0] == RistrettoPoint::identity());
        self.core.attr_points[0] = self.public_attrs.get_point();
    }

    /// Verifies the given `proof` over the accrued attributes using the given `key_pair`.
    pub fn verify(
        mut self,
        key_pair: &CredentialKeyPair,
        proof: &PresentationProof,
    ) -> Result<(), VerificationFailure> {
        self.finalize_public_attrs();

        let PresentationProofCommitments {
            C_x0,
            C_x1,
            C_V,
            C_y,
        } = &proof.commitments;

        if C_y.len() != self.core.attr_points.len() {
            return Err(VerificationFailure);
        }

        let CredentialPrivateKey { W, x0, x1, y, .. } = key_pair.private_key();

        let mut Z = C_V - W - x0 * C_x0 - x1 * C_x1;
        for (yn, C_yn) in y.iter().zip(C_y.iter()) {
            Z -= yn * C_yn;
        }
        // Incorporate public attributes here so the server can check they haven't changed.
        Z -= y[0] * self.core.attr_points[0];

        let public_key = key_pair.public_key();
        let I = public_key.I(self.core.attr_points.len());
        let mut point_args = self
            .core
            .prepare_non_attribute_point_args(I, &proof.commitments);

        for attr in &self.core.attributes {
            let &AttributeRef {
                first_point_index,
                second_point_index,
                key_index,
            } = attr;
            point_args.add(&format!("C_y{}", first_point_index), C_y[first_point_index]);

            if key_index.is_some() {
                point_args.add(
                    &format!("E_A{}", first_point_index),
                    self.core.attr_points[first_point_index],
                );
                point_args.add(
                    &format!("-E_A{}", first_point_index),
                    -self.core.attr_points[first_point_index],
                );
                point_args.add(
                    &format!("C_y{0}-E_A{0}", second_point_index),
                    C_y[second_point_index] - self.core.attr_points[second_point_index],
                );
            } else {
                // Check that the revealed attributes match the original issuance.
                Z -= y[first_point_index] * self.core.attr_points[first_point_index];
            }
        }

        point_args.add("Z", Z);

        match self.core.get_poksho_statement().verify_proof(
            &proof.poksho_proof,
            &point_args,
            self.core.authenticated_message,
        ) {
            Err(_) => Err(VerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}
