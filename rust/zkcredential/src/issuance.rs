//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The generation and verification of credential issuance proofs.
//!
//! When the issuing server issues a credential, it also generates a proof that the credential
//! covers the correct attributes. The client receives the proof and credential together, verifies
//! the proof, and extracts the credential. By providing the same attributes in the same order, the
//! generation and verification procedures have parallel invocations. The size of the proof scales
//! linearly with the number of attributes.
//!
//! Credential issuance is defined in Chase-Perrin-Zaverucha section 3.2.

pub mod blind;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use poksho::{ShoApi, ShoHmacSha256};
use serde::{Deserialize, Serialize};

use crate::attributes::{Attribute, PublicAttribute};
use crate::credentials::{
    Credential, CredentialKeyPair, CredentialPublicKey, SystemParams, NUM_SUPPORTED_ATTRS,
};
use crate::sho::ShoExt;
use crate::{VerificationFailure, RANDOMNESS_LEN};

/// Contains a [`Credential`] along with a proof of its validity.
///
/// Use [`IssuanceProofBuilder`] to validate and extract the credential.
#[derive(Serialize, Deserialize)]
pub struct IssuanceProof {
    credential: Credential,
    poksho_proof: Vec<u8>,
}

/// Used to generate and verify issuance proofs.
///
/// The same type is used for both generation and verification; the issuing server will end by
/// calling [`issue`](Self::issue) and the client by calling [`verify`](Self::verify).
pub struct IssuanceProofBuilder<'a> {
    public_attrs: ShoHmacSha256,
    // Directly accessed by BlindIssuanceProofBuilder.
    attr_points: Vec<RistrettoPoint>,
    authenticated_message: &'a [u8],
}

impl<'a> IssuanceProofBuilder<'a> {
    /// Initializes a new proof builder.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    pub fn new(label: &[u8]) -> Self {
        Self::with_authenticated_message(label, &[])
    }

    /// Initializes the proof builder with a message that must match between the issuing server and
    /// the client.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    /// `message`, however, is not an attribute and will not be part of the resulting credential; it
    /// is merely part of the proof. This could, for example, be used to distinguish multiple proofs
    /// that produce the same kind of credential.
    pub fn with_authenticated_message(label: &[u8], message: &'a [u8]) -> Self {
        Self {
            public_attrs: ShoHmacSha256::new(label),
            // Reserve the first point for public attributes
            attr_points: vec![RistrettoPoint::identity()],
            authenticated_message: message,
        }
    }

    /// Adds a public attribute to the credential.
    ///
    /// This is order-sensitive.
    pub fn add_public_attribute(mut self, attr: &dyn PublicAttribute) -> Self {
        attr.hash_into(&mut self.public_attrs);
        self.public_attrs.ratchet();
        self
    }

    /// Adds an attribute to the credential.
    ///
    /// This is order-sensitive.
    pub fn add_attribute(mut self, attr: &dyn Attribute) -> Self {
        self.attr_points.extend(attr.as_points());
        assert!(
            self.attr_points.len() <= NUM_SUPPORTED_ATTRS,
            "more than {} hidden attribute points not supported",
            NUM_SUPPORTED_ATTRS - 1
        );
        self
    }

    fn get_poksho_statement(&self) -> poksho::Statement {
        // See Chase-Perrin-Zaverucha section 3.2.
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
        st.add("G_V-I", &G_V_minus_I_terms[..2 + self.attr_points.len()]);

        // V = w * G_w + x0 * U + x1 * tU + sum(yi * Mi, i = 0..n)
        let V_terms: [_; NUM_SUPPORTED_ATTRS + 3] = [
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
        st.add("V", &V_terms[..3 + self.attr_points.len()]);
        st
    }

    fn finalize_public_attrs(&mut self) {
        debug_assert!(self.attr_points[0] == RistrettoPoint::identity());
        self.attr_points[0] = self.public_attrs.get_point();
    }

    /// Generates a [`poksho::PointArgs`] to be used in the final proof.
    ///
    /// `total_attr_count` is passed in for [blind issuance](blind::BlindIssuanceProofBuilder), in
    /// which case the caller may provide additional attributes.
    fn prepare_scalar_args(
        &self,
        key_pair: &CredentialKeyPair,
        total_attr_count: usize,
    ) -> poksho::ScalarArgs {
        assert!(
            total_attr_count <= NUM_SUPPORTED_ATTRS,
            "should have been enforced by the caller"
        );

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.private_key().w);
        scalar_args.add("wprime", key_pair.private_key().wprime);
        scalar_args.add("x0", key_pair.private_key().x0);
        scalar_args.add("x1", key_pair.private_key().x1);

        let y_names: [_; NUM_SUPPORTED_ATTRS] = ["y0", "y1", "y2", "y3", "y4", "y5", "y6"];
        for (name, value) in y_names
            .iter()
            .take(total_attr_count)
            .zip(key_pair.private_key().y.iter())
        {
            scalar_args.add(name, *value);
        }
        scalar_args
    }

    /// Generates a [`poksho::PointArgs`] to be used in the final proof.
    ///
    /// The `credential` argument may be `None` when used for [blind
    /// issuance](blind::BlindIssuanceProofBuilder), in which case the caller is responsible for
    /// adding its own points representing the credential.
    fn prepare_point_args(
        &self,
        key: &CredentialPublicKey,
        total_attr_count: usize,
        credential: Option<&Credential>,
    ) -> poksho::PointArgs {
        let system = SystemParams::get_hardcoded();
        assert!(
            total_attr_count <= NUM_SUPPORTED_ATTRS,
            "should have been enforced by the caller"
        );

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key.C_W);
        point_args.add("G_w", system.G_w);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_V-I", system.G_V - key.I(total_attr_count));
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);

        let G_y_names: [_; NUM_SUPPORTED_ATTRS] =
            ["G_y0", "G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6"];
        for (name, value) in G_y_names
            .iter()
            .take(total_attr_count)
            .zip(system.G_y.iter())
        {
            point_args.add(name, *value);
        }

        if let Some(credential) = credential {
            point_args.add("V", credential.V);
            point_args.add("U", credential.U);
            point_args.add("tU", credential.t * credential.U);
        }

        let M_names: [_; NUM_SUPPORTED_ATTRS] = ["M0", "M1", "M2", "M3", "M4", "M5", "M6"];
        for (name, value) in M_names.iter().zip(&self.attr_points) {
            point_args.add(name, *value);
        }
        point_args
    }

    /// Issues a new credential over the accumulated attributes using the given `key_pair`.
    ///
    /// `randomness` ensures several important properties:
    /// - The generated credential is randomized (non-deterministic).
    /// - The issuance proof uses a random nonce.
    ///
    /// It is critical that different randomness is used each time a credential is issued. Failing
    /// to do so effectively reveals the server's private key.
    pub fn issue(
        mut self,
        key_pair: &CredentialKeyPair,
        randomness: [u8; RANDOMNESS_LEN],
    ) -> IssuanceProof {
        self.finalize_public_attrs();

        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_Issuance_20230410");
        sho.absorb_and_ratchet(&randomness);
        let credential = key_pair
            .private_key()
            .credential_core(&self.attr_points, &mut sho);

        let scalar_args = self.prepare_scalar_args(key_pair, self.attr_points.len());

        let point_args = self.prepare_point_args(
            key_pair.public_key(),
            self.attr_points.len(),
            Some(&credential),
        );

        let poksho_proof = self
            .get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                self.authenticated_message,
                &sho.squeeze_and_ratchet(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        IssuanceProof {
            poksho_proof,
            credential,
        }
    }

    /// Verifies the given `proof` over the accrued attributes using the given `public_key`.
    ///
    /// On successful verification, returns the [`Credential`] that was just proven valid.
    pub fn verify(
        mut self,
        public_key: &CredentialPublicKey,
        proof: IssuanceProof,
    ) -> Result<Credential, VerificationFailure> {
        self.finalize_public_attrs();
        let point_args =
            self.prepare_point_args(public_key, self.attr_points.len(), Some(&proof.credential));
        match self.get_poksho_statement().verify_proof(
            &proof.poksho_proof,
            &point_args,
            self.authenticated_message,
        ) {
            Err(_) => Err(VerificationFailure),
            Ok(_) => Ok(proof.credential),
        }
    }
}
