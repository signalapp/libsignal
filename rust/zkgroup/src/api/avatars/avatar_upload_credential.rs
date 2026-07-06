//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides AvatarUploadCredential and related types.
//!
//! AvatarUploadCredential is a MAC-based credential over:
//! - a timestamp, truncated to day granularity (public, chosen by server at issuance)
//! - a Pedersen commitment `Cm = [aci_scalar]*H1 + [rotation_id]*H2 + [a1]*H3 + [a2]*H4`
//!   (blinded at issuance, revealed for verification), where `(a1, a2)` are the two secret scalars
//!   of the account's ZK credential key.
//!
//! The commitment Cm hides which ACI produced it, even against a harvest-now-decrypt-later quantum
//! adversary that records the ZK credential public key `A = a1*G_a1 + a2*G_a2`: breaking the
//! discrete log of `A` yields only the single relation `a1*g_a1 + a2*g_a2`, which leaves `(a1, a2)`
//! underdetermined and so keeps the `[a1]*H3 + [a2]*H4` blinding terms hidden (provided
//! `(G_a1, G_a2)` are independent of `(H3, H4)`). Because `(a1, a2)` are derived from a 256-bit
//! seed (see [`crate::zk_credential_key`]), this hiding is *computational* at the ~128-bit
//! post-quantum level, not information-theoretic.
//!
//! At issuance, the client already knows `rotation_id` (the server returns it when the client sets
//! its ZK credential key), so the client builds the full `Cm = [aci_scalar]*H1 + [rotation_id]*H2 +
//! [a1]*H3 + [a2]*H4` directly, blinds it, and provides a standalone proof that the blinded Cm is
//! well-formed for the authenticated ACI and the ZK credential key known to the server. The server
//! verifies that proof against its own `rotation_id` (it subtracts `[rotation_id]*H2` while
//! reconstructing the proof's adjusted point), which forces the client to have used the server's
//! value — so the server still controls the avatar slot rotation ID, and still never learns Cm
//! because it stays blinded.
//!
//! At presentation, the credential reveals Cm to the verifying server along with a standard
//! credential validity proof.

// We use upper case variable names for curve points by convention.
#![allow(non_snake_case)]

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use curve25519_dalek_signal::scalar::Scalar;
use curve25519_dalek_signal::traits::VartimeMultiscalarMul as _;
use partial_default::PartialDefault;
use poksho::ShoApi;
use poksho::shoapi::ShoApiExt as _;
use serde::{Deserialize, Serialize};
use zkcredential::attributes::Domain as _;

use crate::common::serialization::ReservedByte;
use crate::common::sho::Sho;
use crate::common::simple_types::*;
use crate::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use crate::zk_credential_key::{ZkCredentialKeyDomain, ZkCredentialKeyPair, ZkCredentialPublicKey};
use crate::{RANDOMNESS_LEN, ZkGroupVerificationFailure};

// ---------------------------------------------------------------------------
// System parameters: Pedersen commitment generators
// ---------------------------------------------------------------------------

/// Independent generators for the avatar commitment `Cm = [aci_scalar]*H1 + [rotation_id]*H2 +
/// [a1]*H3 + [a2]*H4`.
///
/// Derived deterministically from a fixed label. H1..H4 must be independent of each other and
/// independent of generators used elsewhere (e.g., G_j3 from profile key commitments, and crucially
/// the ZK credential key's `(G_a1, G_a2)` — `(H3, H4)` being independent of `(G_a1, G_a2)` is what
/// prevents the public key relation from directly revealing the commitment's blinding terms).
struct AvatarCommitmentParams {
    H1: RistrettoPoint,
    H2: RistrettoPoint,
    H3: RistrettoPoint,
    H4: RistrettoPoint,
}

impl AvatarCommitmentParams {
    fn get_hardcoded() -> Self {
        let mut sho = Sho::new_seed(b"20260602_Signal_AvatarUploadCredential_CommitmentParams");
        Self {
            H1: sho.get_point(),
            H2: sho.get_point(),
            H3: sho.get_point(),
            H4: sho.get_point(),
        }
    }
}

// ---------------------------------------------------------------------------
// Commitment point (wraps a RistrettoPoint, implements RevealedAttribute)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, PartialDefault)]
pub struct CommitmentPoint(RistrettoPoint);

impl zkcredential::attributes::RevealedAttribute for CommitmentPoint {
    fn as_point(&self) -> RistrettoPoint {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Credential label and Cm well-formedness proof label
// ---------------------------------------------------------------------------

const CREDENTIAL_LABEL: &[u8] = b"20260329_Signal_AvatarUploadCredential";
const CM_WELL_FORMEDNESS_PROOF_LABEL: &[u8] =
    b"20260329_Signal_AvatarUploadCredential_CmWellFormednessProof";

// ---------------------------------------------------------------------------
// Cm well-formedness proof: proves blinded Cm is well-formed
// ---------------------------------------------------------------------------

/// The standalone proof that the blinded Cm is well-formed.
///
/// Proves knowledge of (r, a1, a2) such that:
///   D1      = r * G
///   D2_adj       = r * Y + a1 * H3 + a2 * H4   where D2_adj = D2 - aci_scalar * H1 - rotation_id * H2
///   ZkCredKeyPub = a1 * G_a1 + a2 * G_a2
///
/// The shared "a1"/"a2" labels across eqs 2-3 enforce that the blinded Cm uses the same `(a1, a2)`
/// as the known ZK credential public key (`ZkCredKeyPub`, i.e. `A = a1*G_a1 + a2*G_a2`).
#[derive(Serialize, Deserialize, Clone, PartialDefault)]
struct CmWellFormednessProof {
    poksho_proof: Vec<u8>,
}

impl CmWellFormednessProof {
    fn statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        // "G" is the Ristretto basepoint, pre-assigned at index 0 by poksho.
        st.add("D1", &[("r", "G")]);
        st.add("D2_adj", &[("r", "Y"), ("a1", "H3"), ("a2", "H4")]);
        st.add("ZkCredKeyPub", &[("a1", "G_a1"), ("a2", "G_a2")]);
        st
    }

    fn prove(
        blinding_nonce: Scalar,
        a1: Scalar,
        a2: Scalar,
        blinded_cm: &zkcredential::issuance::blind::BlindedPoint,
        D2_adj: RistrettoPoint,
        blinding_public_key: &zkcredential::issuance::blind::BlindingPublicKey,
        zk_credential_key_pub: RistrettoPoint,
        randomness: [u8; RANDOMNESS_LEN],
    ) -> Self {
        // `D2_adj = blinded_cm.D2 - [aci_scalar]*H1 - [rotation_id]*H2` is supplied by the caller,
        // which already computed those public terms while building Cm — so there are no scalar
        // multiplications here. The verifier reconstructs the same point from public values (see
        // `verify`); that reconstruction is what enforces soundness.
        let params = AvatarCommitmentParams::get_hardcoded();
        let [G_a1, G_a2] = ZkCredentialKeyDomain::G_a();

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("r", blinding_nonce);
        scalar_args.add("a1", a1);
        scalar_args.add("a2", a2);

        // Note: "G" is pre-assigned by poksho as the Ristretto basepoint (index 0),
        // so it must NOT be included in point_args.
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", blinding_public_key.Y);
        point_args.add("H3", params.H3);
        point_args.add("H4", params.H4);
        point_args.add("G_a1", G_a1);
        point_args.add("G_a2", G_a2);

        point_args.add("D1", blinded_cm.D1);
        point_args.add("D2_adj", D2_adj);
        point_args.add("ZkCredKeyPub", zk_credential_key_pub);

        let poksho_proof = Self::statement()
            .prove(
                &scalar_args,
                &point_args,
                CM_WELL_FORMEDNESS_PROOF_LABEL,
                &randomness,
            )
            .expect("valid proof");

        Self { poksho_proof }
    }

    fn verify(
        &self,
        blinded_cm: &zkcredential::issuance::blind::BlindedPoint,
        blinding_public_key: &zkcredential::issuance::blind::BlindingPublicKey,
        aci_scalar: Scalar,
        rotation_id: u64,
        zk_credential_key_pub: RistrettoPoint,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let params = AvatarCommitmentParams::get_hardcoded();
        let [G_a1, G_a2] = ZkCredentialKeyDomain::G_a();
        //  Both scalars are public, so vartime is safe.
        let D2_adj = blinded_cm.D2
            - RistrettoPoint::vartime_multiscalar_mul(
                [aci_scalar, Scalar::from(rotation_id)],
                [params.H1, params.H2],
            );

        // Note: "G" is pre-assigned by poksho as the Ristretto basepoint (index 0),
        // so it must NOT be included in point_args.
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", blinding_public_key.Y);
        point_args.add("H3", params.H3);
        point_args.add("H4", params.H4);
        point_args.add("G_a1", G_a1);
        point_args.add("G_a2", G_a2);

        point_args.add("D1", blinded_cm.D1);
        point_args.add("D2_adj", D2_adj);
        point_args.add("ZkCredKeyPub", zk_credential_key_pub);

        Self::statement()
            .verify_proof(
                &self.poksho_proof,
                &point_args,
                CM_WELL_FORMEDNESS_PROOF_LABEL,
            )
            .map_err(|_| ZkGroupVerificationFailure)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Interprets a 128-bit ACI as a scalar for use in the avatar commitment.
///
/// The UUID bytes are zero-padded to 32 bytes. Since the group order is ~2^252, this is
/// injective on the 128-bit input range (no reduction occurs). No hash is needed because
/// the ACI is public to both parties — we only need injectivity, not uniformity.
fn aci_to_scalar(aci: libsignal_core::Aci) -> Scalar {
    let uuid_bytes = uuid::Uuid::from(aci).into_bytes();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..16].copy_from_slice(&uuid_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

/// Computes the avatar upload commitment `Cm = [aci_scalar]*H1 + [rotation_id]*H2 + [a1]*H3 +
/// [a2]*H4`, returning it alongside the *public offset* `[aci_scalar]*H1 + [rotation_id]*H2`.
fn avatar_commitment(
    aci_scalar: Scalar,
    secrets: (Scalar, Scalar),
    rotation_id: u64,
) -> (RistrettoPoint, RistrettoPoint) {
    let params = AvatarCommitmentParams::get_hardcoded();
    let (a1, a2) = secrets;
    // aci_scalar and rotation_id are public, so vartime is safe for the offset.
    let public_offset = RistrettoPoint::vartime_multiscalar_mul(
        [aci_scalar, Scalar::from(rotation_id)],
        [params.H1, params.H2],
    );
    // a1 and a2 are secret, so use constant-time scalar multiplication for the blinding terms.
    let cm = public_offset + a1 * params.H3 + a2 * params.H4;
    (cm, public_offset)
}

fn check_avatar_upload_credential_redemption_time(
    redemption_time: Timestamp,
    current_time: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    let acceptable_start_time = redemption_time
        .checked_sub_seconds(crate::SECONDS_PER_DAY)
        .ok_or(ZkGroupVerificationFailure)?;
    let acceptable_end_time = redemption_time
        .checked_add_seconds(2 * crate::SECONDS_PER_DAY)
        .ok_or(ZkGroupVerificationFailure)?;

    if !(acceptable_start_time..=acceptable_end_time).contains(&current_time) {
        return Err(ZkGroupVerificationFailure);
    }

    Ok(())
}

/// Computes the full avatar commitment `Cm = [aci_scalar]*H1 + [rotation_id]*H2 + [a1]*H3 +
/// [a2]*H4`, discarding the public offset. Used by tests that only need the commitment.
#[cfg(test)]
fn compute_cm(aci_scalar: Scalar, secrets: (Scalar, Scalar), rotation_id: u64) -> RistrettoPoint {
    avatar_commitment(aci_scalar, secrets, rotation_id).0
}

// ---------------------------------------------------------------------------
// Request context (client-side state, not sent over the wire)
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AvatarUploadCredentialRequestContext {
    reserved: ReservedByte,
    blinded_cm: zkcredential::issuance::blind::BlindedPoint,
    key_pair: zkcredential::issuance::blind::BlindingKeyPair,
    cm_well_formedness_proof: CmWellFormednessProof,
    cm: RistrettoPoint,
}

impl AvatarUploadCredentialRequestContext {
    /// Constructs a new request context.
    ///
    /// `zk_credential_key_pair` is the account's long-term Ristretto ZK credential key pair.
    ///
    /// `rotation_id` is the server-chosen avatar slot rotation ID. The client already holds it (the
    /// server returns it when the client sets its ZK credential key), so the client folds it into
    /// the full commitment `Cm = [aci]*H1 + [rotation_id]*H2 + [a1]*H3 + [a2]*H4` here.
    /// The server later verifies the well-formedness proof against its own `rotation_id`, which
    /// forces the client to have used the server's value.
    pub fn new(
        aci: libsignal_core::Aci,
        zk_credential_key_pair: &ZkCredentialKeyPair,
        rotation_id: u64,
        randomness: RandomnessBytes,
    ) -> Self {
        let (a1, a2) = zk_credential_key_pair.secrets();
        let zk_credential_key_pub = zk_credential_key_pair.public_key().point();

        let mut sho = poksho::ShoHmacSha256::new(b"20260329_Signal_AvatarUploadCredentialRequest");
        sho.absorb_and_ratchet(&randomness);

        let aci_scalar = aci_to_scalar(aci);
        let (cm, public_offset) = avatar_commitment(aci_scalar, (a1, a2), rotation_id);
        let cm_point = CommitmentPoint(cm);

        let key_pair = zkcredential::issuance::blind::BlindingKeyPair::generate(&mut sho);
        let blinded_cm_with_nonce = key_pair.blind(&cm_point, &mut sho);

        // Extract the blinding nonce for the Cm well-formedness proof.
        let blinding_nonce = blinded_cm_with_nonce.r.0;
        // Strip the blinding_nonce by making a BlindedPoint<WithoutNonce>
        let blinded_cm: zkcredential::issuance::blind::BlindedPoint = blinded_cm_with_nonce.into();

        // The proof's adjusted point is the blinded D2 with the public terms removed. Both terms
        // are already in `public_offset`, so this is a bare point subtraction (no scalar muls).
        let D2_adj = blinded_cm.D2 - public_offset;

        let proof_randomness: [u8; RANDOMNESS_LEN] = sho.squeeze_and_ratchet_as_array();

        let cm_well_formedness_proof = CmWellFormednessProof::prove(
            blinding_nonce,
            a1,
            a2,
            &blinded_cm,
            D2_adj,
            key_pair.public_key(),
            zk_credential_key_pub,
            proof_randomness,
        );

        Self {
            reserved: Default::default(),
            blinded_cm,
            key_pair,
            cm_well_formedness_proof,
            cm,
        }
    }

    pub fn get_request(&self) -> AvatarUploadCredentialRequest {
        AvatarUploadCredentialRequest {
            reserved: Default::default(),
            blinded_cm: self.blinded_cm,
            public_key: *self.key_pair.public_key(),
            cm_well_formedness_proof: self.cm_well_formedness_proof.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Request (sent to the issuing server)
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AvatarUploadCredentialRequest {
    reserved: ReservedByte,
    blinded_cm: zkcredential::issuance::blind::BlindedPoint,
    public_key: zkcredential::issuance::blind::BlindingPublicKey,
    cm_well_formedness_proof: CmWellFormednessProof,
}

impl AvatarUploadCredentialRequest {
    /// Server-side: verify the Cm well-formedness proof and issue a blinded credential.
    ///
    /// The server must authenticate the client to obtain `aci`, and must supply
    /// `zk_credential_key_pub` from its record for that account. The Cm well-formedness proof
    /// binds the blinded commitment to this `zk_credential_key_pub`, so passing the wrong
    /// value will fail proof verification.
    ///
    /// `rotation_id` is a server-chosen value that the client must already have folded into the
    /// commitment `Cm = [aci]*H1 + [rotation_id]*H2 + [a1]*H3 + [a2]*H4`. The server
    /// supplies its own `rotation_id` here; the well-formedness proof is verified against it, so a
    /// client that committed to a different value will fail issuance. The server never learns Cm
    /// (it stays blinded) yet still controls the rotation ID.
    ///
    /// **Client-enforced invariant**: The client must enforce that the server
    /// only changes `rotation_id` when the client's ZK credential key is
    /// rotated. Otherwise a malicious server can fingerprint a client across
    /// credential issuances by varying `rotation_id` while the client's ACI and
    /// ZK credential key are stable: the server can recompute
    /// `[delta_rotation_id]*H2` for any candidate (aci, zk_credential_key_pub) pair and check
    /// whether the observed Cm-delta matches (of course it would have to test
    /// all pairs because it wouldn't know which ones had the same (aci,zk_credential_key_pub),
    /// but finding a match would still be meaningful). With this invariant,
    /// observing two distinct rotation IDs for the same account proves the ZK
    /// credential key has rotated, which severs the linkability of pre- and
    /// post-rotation avatar slots.
    pub fn issue(
        &self,
        aci: libsignal_core::Aci,
        zk_credential_key_pub: &ZkCredentialPublicKey,
        rotation_id: u64,
        redemption_time: Timestamp,
        params: &GenericServerSecretParams,
        randomness: RandomnessBytes,
    ) -> Result<AvatarUploadCredentialResponse, ZkGroupVerificationFailure> {
        if !redemption_time.is_day_aligned() {
            return Err(ZkGroupVerificationFailure);
        }

        // Verify the Cm well-formedness proof against the server-supplied zk_credential_key_pub and
        // the server's own rotation_id. The verifier strips `[aci]*H1 + [rotation_id]*H2` from the
        // blinded point, so a mismatched rotation_id fails here.
        let aci_scalar = aci_to_scalar(aci);
        self.cm_well_formedness_proof.verify(
            &self.blinded_cm,
            &self.public_key,
            aci_scalar,
            rotation_id,
            zk_credential_key_pub.point(),
        )?;

        // Issue the blind credential over (timestamp, Cm). The blinded point already commits to the
        // full Cm (including [rotation_id]*H2), so no server-side adjustment is needed.
        let blinded_credential =
            zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&redemption_time)
                .add_blinded_revealed_attribute(&self.blinded_cm)
                .issue(&params.credential_key, &self.public_key, randomness);

        Ok(AvatarUploadCredentialResponse {
            reserved: Default::default(),
            redemption_time,
            blinded_credential,
        })
    }
}

// ---------------------------------------------------------------------------
// Response (sent from issuing server to client)
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AvatarUploadCredentialResponse {
    reserved: ReservedByte,
    redemption_time: Timestamp,
    blinded_credential: zkcredential::issuance::blind::BlindedIssuanceProof,
}

// ---------------------------------------------------------------------------
// Receive (client-side: verify and unblind)
// ---------------------------------------------------------------------------

impl AvatarUploadCredentialRequestContext {
    /// Verifies the issuing server's response and produces a usable [`AvatarUploadCredential`].
    ///
    /// The server chose the `redemption_time` and embedded it in `response`. The client doesn't
    /// need to predict it, it only needs to confirm that the credential is usable *now*, since the
    /// verifying server applies the same window (see [`AvatarUploadCredentialPresentation::verify`]).
    /// `current_time` is the client's view of wall-clock time; the redemption time must be day-aligned
    /// and fall inside the redemption window relative to it.
    pub fn receive(
        self,
        response: AvatarUploadCredentialResponse,
        params: &GenericServerPublicParams,
        current_time: Timestamp,
    ) -> Result<AvatarUploadCredential, ZkGroupVerificationFailure> {
        if !response.redemption_time.is_day_aligned() {
            return Err(ZkGroupVerificationFailure);
        }
        check_avatar_upload_credential_redemption_time(response.redemption_time, current_time)?;

        // The blinded point already commits to the full Cm (the client folded in [rotation_id]*H2
        // at request time), so we verify the issuance directly against it — no adjustment needed.
        let credential = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_public_attribute(&response.redemption_time)
            .add_blinded_revealed_attribute(&self.blinded_cm)
            .verify(
                &params.credential_key,
                &self.key_pair,
                response.blinded_credential,
            )
            .map_err(|_| ZkGroupVerificationFailure)?;

        Ok(AvatarUploadCredential {
            reserved: Default::default(),
            redemption_time: response.redemption_time,
            credential,
            cm: CommitmentPoint(self.cm),
        })
    }
}

// ---------------------------------------------------------------------------
// Credential (client-side state after unblinding)
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AvatarUploadCredential {
    reserved: ReservedByte,
    redemption_time: Timestamp,
    credential: zkcredential::credentials::Credential,
    cm: CommitmentPoint,
}

impl AvatarUploadCredential {
    pub fn present(
        &self,
        server_params: &GenericServerPublicParams,
        randomness: RandomnessBytes,
    ) -> AvatarUploadCredentialPresentation {
        AvatarUploadCredentialPresentation {
            version: Default::default(),
            redemption_time: self.redemption_time,
            cm: self.cm,
            proof: zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
                .add_revealed_attribute(&self.cm)
                .present(&server_params.credential_key, &self.credential, randomness),
        }
    }

    /// The Pedersen commitment `cm`, used as a stable unlinkable identifier.
    pub fn cm(&self) -> CommitmentPoint {
        self.cm
    }

    /// The compressed-Ristretto encoding of Pedersen commitment `cm`, suitable for bridge consumers.
    pub fn cm_bytes(&self) -> [u8; 32] {
        self.cm.0.compress().to_bytes()
    }

    /// The redemption time the issuing server chose for this credential.
    pub fn redemption_time(&self) -> Timestamp {
        self.redemption_time
    }
}

// ---------------------------------------------------------------------------
// Presentation (sent to verifying server)
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AvatarUploadCredentialPresentation {
    version: ReservedByte,
    redemption_time: Timestamp,
    cm: CommitmentPoint,
    proof: zkcredential::presentation::PresentationProof,
}

impl AvatarUploadCredentialPresentation {
    pub fn verify(
        &self,
        current_time: Timestamp,
        server_params: &GenericServerSecretParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        // Check timestamp window: [-1 day, +2 days]
        check_avatar_upload_credential_redemption_time(self.redemption_time, current_time)?;

        zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
            .add_public_attribute(&self.redemption_time)
            .add_revealed_attribute(&self.cm)
            .verify(&server_params.credential_key, &self.proof)
            .map_err(|_| ZkGroupVerificationFailure)
    }

    /// The Pedersen commitment `cm`, used as a stable unlinkable identifier.
    pub fn cm(&self) -> CommitmentPoint {
        self.cm
    }

    /// The compressed-Ristretto encoding of Pedersen commitment `cm`, suitable for bridge consumers.
    pub fn cm_bytes(&self) -> [u8; 32] {
        self.cm.0.compress().to_bytes()
    }

    pub fn redemption_time(&self) -> Timestamp {
        self.redemption_time
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SECONDS_PER_DAY, Timestamp};

    const DAY_ALIGNED_TIMESTAMP: Timestamp = Timestamp::from_epoch_seconds(1681344000); // 2023-04-13 00:00:00 UTC
    const ACI: uuid::Uuid = uuid::uuid!("c0fc16e4-bae5-4343-9f0d-e7ecf4251343");
    const ROTATION_ID: u64 = 1;
    const SERVER_SECRET_RAND: RandomnessBytes = [0xA0; RANDOMNESS_LEN];
    const REQUEST_RAND: RandomnessBytes = [0xA1; RANDOMNESS_LEN];
    const ISSUE_RAND: RandomnessBytes = [0xA2; RANDOMNESS_LEN];
    const PRESENT_RAND: RandomnessBytes = [0xA3; RANDOMNESS_LEN];
    const ZK_CRED_KEY_RAND: RandomnessBytes = [0x42; RANDOMNESS_LEN];
    const WRONG_ZK_CRED_KEY_RAND: RandomnessBytes = [0x99; RANDOMNESS_LEN];

    fn zk_credential_key_pair() -> ZkCredentialKeyPair {
        ZkCredentialKeyPair::generate(ZK_CRED_KEY_RAND)
    }

    fn zk_credential_key_pub() -> ZkCredentialPublicKey {
        zk_credential_key_pair().public_key()
    }

    fn zk_credential_key_secrets() -> (Scalar, Scalar) {
        zk_credential_key_pair().secrets()
    }

    fn server_secret_params() -> GenericServerSecretParams {
        GenericServerSecretParams::generate(SERVER_SECRET_RAND)
    }

    fn generate_credential(redemption_time: Timestamp) -> AvatarUploadCredential {
        generate_credential_with_rotation_id(redemption_time, ROTATION_ID)
    }

    fn generate_credential_with_rotation_id(
        redemption_time: Timestamp,
        rotation_id: u64,
    ) -> AvatarUploadCredential {
        let aci = libsignal_core::Aci::from(ACI);
        let request_context = AvatarUploadCredentialRequestContext::new(
            aci,
            &zk_credential_key_pair(),
            rotation_id,
            REQUEST_RAND,
        );
        let request = request_context.get_request();

        let response = request
            .issue(
                aci,
                &zk_credential_key_pub(),
                rotation_id,
                redemption_time,
                &server_secret_params(),
                ISSUE_RAND,
            )
            .expect("issuance should succeed");

        let server_public_params = server_secret_params().get_public_params();
        request_context
            .receive(response, &server_public_params, redemption_time)
            .expect("credential should be valid")
    }

    /// Builds an in-flight request/response pair without consuming the request context, so tests
    /// can exercise `receive` with adversarial `current_time` values.
    fn issue_for_receive_test(
        redemption_time: Timestamp,
    ) -> (
        AvatarUploadCredentialRequestContext,
        AvatarUploadCredentialResponse,
    ) {
        let aci = libsignal_core::Aci::from(ACI);
        let request_context = AvatarUploadCredentialRequestContext::new(
            aci,
            &zk_credential_key_pair(),
            ROTATION_ID,
            REQUEST_RAND,
        );
        let response = request_context
            .get_request()
            .issue(
                aci,
                &zk_credential_key_pub(),
                ROTATION_ID,
                redemption_time,
                &server_secret_params(),
                ISSUE_RAND,
            )
            .expect("issuance should succeed");
        (request_context, response)
    }

    #[test]
    fn test_happy_path() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);

        presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect("presentation should be valid");
    }

    #[test]
    fn test_context_serialization_does_not_include_raw_zk_credential_key_secret() {
        let aci = libsignal_core::Aci::from(ACI);
        let request_context = AvatarUploadCredentialRequestContext::new(
            aci,
            &zk_credential_key_pair(),
            ROTATION_ID,
            REQUEST_RAND,
        );
        let serialized = crate::serialize(&request_context);

        let (a1, a2) = zk_credential_key_secrets();
        for secret_bytes in [a1.to_bytes(), a2.to_bytes()] {
            assert!(
                !serialized
                    .windows(secret_bytes.len())
                    .any(|window| window == secret_bytes),
                "request context serialization should not contain a raw ZK credential key secret"
            );
        }
    }

    #[test]
    fn test_server_verify_expiration() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);

        presentation
            .verify(
                DAY_ALIGNED_TIMESTAMP.sub_seconds(SECONDS_PER_DAY + 1),
                &server_secret_params(),
            )
            .expect_err("credential should not be valid 24h before redemption time");

        presentation
            .verify(
                DAY_ALIGNED_TIMESTAMP.add_seconds(2 * SECONDS_PER_DAY + 1),
                &server_secret_params(),
            )
            .expect_err("credential should not be valid after expiration (2 days later)");
    }

    #[test]
    fn test_server_verify_wrong_cm() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let valid_presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);

        // Tamper with Cm
        let wrong_cm = Sho::new(b"wrong", b"cm").get_point();
        let invalid_presentation = AvatarUploadCredentialPresentation {
            cm: CommitmentPoint(wrong_cm),
            ..valid_presentation
        };
        invalid_presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect_err("credential should not be valid with altered Cm");
    }

    #[test]
    fn test_server_verify_wrong_redemption_time() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let valid_presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);

        let invalid_presentation = AvatarUploadCredentialPresentation {
            redemption_time: DAY_ALIGNED_TIMESTAMP.add_seconds(1),
            ..valid_presentation
        };
        invalid_presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect_err("credential should not be valid with altered redemption_time");
    }

    #[test]
    fn test_issuance_wrong_aci() {
        // Client requests for one ACI, server checks against a different one.
        let client_aci = libsignal_core::Aci::from(ACI);
        let wrong_aci =
            libsignal_core::Aci::from(uuid::uuid!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

        let request_context = AvatarUploadCredentialRequestContext::new(
            client_aci,
            &zk_credential_key_pair(),
            ROTATION_ID,
            REQUEST_RAND,
        );
        let request = request_context.get_request();

        assert!(
            request
                .issue(
                    wrong_aci,
                    &zk_credential_key_pub(),
                    ROTATION_ID,
                    DAY_ALIGNED_TIMESTAMP,
                    &server_secret_params(),
                    ISSUE_RAND,
                )
                .is_err(),
            "issuance should fail with wrong ACI"
        );
    }

    #[test]
    fn test_issuance_wrong_zk_credential_key_pub() {
        let aci = libsignal_core::Aci::from(ACI);
        let request_context = AvatarUploadCredentialRequestContext::new(
            aci,
            &zk_credential_key_pair(),
            ROTATION_ID,
            REQUEST_RAND,
        );
        let request = request_context.get_request();

        // Server has a different ZK credential key on file
        let wrong_zk_credential_key_pub =
            ZkCredentialKeyPair::generate(WRONG_ZK_CRED_KEY_RAND).public_key();

        assert!(
            request
                .issue(
                    aci,
                    &wrong_zk_credential_key_pub,
                    ROTATION_ID,
                    DAY_ALIGNED_TIMESTAMP,
                    &server_secret_params(),
                    ISSUE_RAND,
                )
                .is_err(),
            "issuance should fail with wrong ZK credential key"
        );
    }

    #[test]
    fn test_client_accepts_credential_inside_window() {
        // The client's `current_time` can drift within the redemption window [-1d, +2d] and
        // `receive` must still accept the credential.
        let server_public_params = server_secret_params().get_public_params();
        let current_times = [
            DAY_ALIGNED_TIMESTAMP.sub_seconds(SECONDS_PER_DAY),
            DAY_ALIGNED_TIMESTAMP,
            DAY_ALIGNED_TIMESTAMP.add_seconds(SECONDS_PER_DAY),
            DAY_ALIGNED_TIMESTAMP.add_seconds(2 * SECONDS_PER_DAY),
        ];
        for current_time in current_times {
            let (ctx, response) = issue_for_receive_test(DAY_ALIGNED_TIMESTAMP);
            ctx.receive(response, &server_public_params, current_time)
                .expect("receive should succeed inside the redemption window");
        }
    }

    #[test]
    fn test_client_rejects_credential_outside_window() {
        // Outside the [-1d, +2d] window the client must refuse to accept the credential, even if
        // everything else is in order.
        let server_public_params = server_secret_params().get_public_params();

        // current_time more than 1 day before redemption_time => not yet usable.
        let (ctx, response) = issue_for_receive_test(DAY_ALIGNED_TIMESTAMP);
        assert!(
            ctx.receive(
                response,
                &server_public_params,
                DAY_ALIGNED_TIMESTAMP.sub_seconds(SECONDS_PER_DAY + 1),
            )
            .is_err(),
            "client should reject a credential not yet inside the redemption window"
        );

        // current_time more than 2 days after redemption_time => already expired.
        let (ctx, response) = issue_for_receive_test(DAY_ALIGNED_TIMESTAMP);
        assert!(
            ctx.receive(
                response,
                &server_public_params,
                DAY_ALIGNED_TIMESTAMP.add_seconds(2 * SECONDS_PER_DAY + 1),
            )
            .is_err(),
            "client should reject an already-expired credential"
        );
    }

    #[test]
    fn test_client_rejects_non_day_aligned_redemption_time() {
        // The server-side `issue` API won't issue a non-day-aligned credential, so construct a
        // response directly with a proof that is otherwise valid for the non-day-aligned time.
        // This makes the test specifically cover the receive-side day-alignment check.
        let aci = libsignal_core::Aci::from(ACI);
        let request_context = AvatarUploadCredentialRequestContext::new(
            aci,
            &zk_credential_key_pair(),
            ROTATION_ID,
            REQUEST_RAND,
        );

        let request = request_context.get_request();
        let server_params = server_secret_params();
        let malicious = AvatarUploadCredentialResponse {
            reserved: Default::default(),
            redemption_time: DAY_ALIGNED_TIMESTAMP.add_seconds(3600),
            blinded_credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&DAY_ALIGNED_TIMESTAMP.add_seconds(3600))
                .add_blinded_revealed_attribute(&request.blinded_cm)
                .issue(
                    &server_params.credential_key,
                    &request.public_key,
                    ISSUE_RAND,
                ),
        };
        assert!(
            request_context
                .receive(
                    malicious,
                    &server_secret_params().get_public_params(),
                    DAY_ALIGNED_TIMESTAMP,
                )
                .is_err(),
            "client should reject a non-day-aligned redemption_time"
        );
    }

    #[test]
    fn test_credential_exposes_redemption_time() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        assert_eq!(credential.redemption_time(), DAY_ALIGNED_TIMESTAMP);
    }

    #[test]
    fn test_server_enforces_timestamp_granularity() {
        let aci = libsignal_core::Aci::from(ACI);
        let not_day_aligned = DAY_ALIGNED_TIMESTAMP.add_seconds(3600);

        let request_context = AvatarUploadCredentialRequestContext::new(
            aci,
            &zk_credential_key_pair(),
            ROTATION_ID,
            REQUEST_RAND,
        );
        let request = request_context.get_request();

        assert!(
            request
                .issue(
                    aci,
                    &zk_credential_key_pub(),
                    ROTATION_ID,
                    not_day_aligned,
                    &server_secret_params(),
                    ISSUE_RAND,
                )
                .is_err(),
            "issuance should fail when timestamp is not on a day boundary"
        );
        // The client enforces it too, but this is not tested because the server
        // won't issue a non-aligned credential.
    }

    #[test]
    fn test_commitment_generators_are_pairwise_independent() {
        // HNDL hiding requires the public-key generators (G_a1, G_a2) to be independent of the
        // commitment blinding generators (H3, H4). This is a weak but cheap test to ensure
        // that all generators are different at least.
        let params = AvatarCommitmentParams::get_hardcoded();
        let [G_a1, G_a2] = ZkCredentialKeyDomain::G_a();
        let generators = [params.H1, params.H2, params.H3, params.H4, G_a1, G_a2];

        for g in generators {
            assert_ne!(
                g,
                RistrettoPoint::default(),
                "generator must not be identity"
            );
        }
        for (i, gi) in generators.iter().enumerate() {
            for gj in &generators[i + 1..] {
                assert_ne!(
                    gi, gj,
                    "commitment/key generators must be pairwise distinct"
                );
            }
        }
    }

    #[test]
    fn test_cm_deterministic() {
        // Same (aci, (a1, a2), rotation_id) should produce the same Cm.
        let aci = libsignal_core::Aci::from(ACI);
        let aci_scalar = aci_to_scalar(aci);
        let cm1 = compute_cm(aci_scalar, zk_credential_key_secrets(), ROTATION_ID);
        let cm2 = compute_cm(aci_scalar, zk_credential_key_secrets(), ROTATION_ID);
        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_cm_differs_for_different_aci() {
        let aci1 = libsignal_core::Aci::from(ACI);
        let aci2 = libsignal_core::Aci::from(uuid::uuid!("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        let cm1 = compute_cm(
            aci_to_scalar(aci1),
            zk_credential_key_secrets(),
            ROTATION_ID,
        );
        let cm2 = compute_cm(
            aci_to_scalar(aci2),
            zk_credential_key_secrets(),
            ROTATION_ID,
        );
        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_cm_differs_for_different_zk_credential_key() {
        let aci = libsignal_core::Aci::from(ACI);
        let aci_scalar = aci_to_scalar(aci);
        let secrets1 = ZkCredentialKeyPair::generate(ZK_CRED_KEY_RAND).secrets();
        let secrets2 = ZkCredentialKeyPair::generate(WRONG_ZK_CRED_KEY_RAND).secrets();
        let cm1 = compute_cm(aci_scalar, secrets1, ROTATION_ID);
        let cm2 = compute_cm(aci_scalar, secrets2, ROTATION_ID);
        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_cm_differs_for_different_rotation_id() {
        let aci = libsignal_core::Aci::from(ACI);
        let aci_scalar = aci_to_scalar(aci);
        let cm1 = compute_cm(aci_scalar, zk_credential_key_secrets(), 1);
        let cm2 = compute_cm(aci_scalar, zk_credential_key_secrets(), 2);
        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_issuance_wrong_rotation_id() {
        // Client commits to one rotation_id; server issues against a different one. The
        // well-formedness proof must fail, because the verifier strips the server's rotation_id and
        // is left with a residual [delta]*H2.
        let aci = libsignal_core::Aci::from(ACI);
        let request_context = AvatarUploadCredentialRequestContext::new(
            aci,
            &zk_credential_key_pair(),
            1,
            REQUEST_RAND,
        );
        let request = request_context.get_request();

        assert!(
            request
                .issue(
                    aci,
                    &zk_credential_key_pub(),
                    2,
                    DAY_ALIGNED_TIMESTAMP,
                    &server_secret_params(),
                    ISSUE_RAND,
                )
                .is_err(),
            "issuance should fail when the server's rotation_id differs from the client's"
        );
    }

    #[test]
    fn test_different_rotation_id_produces_different_presentation_cm() {
        let cred_v1 = generate_credential_with_rotation_id(DAY_ALIGNED_TIMESTAMP, 1);
        let cred_v2 = generate_credential_with_rotation_id(DAY_ALIGNED_TIMESTAMP, 2);
        assert_ne!(cred_v1.cm(), cred_v2.cm());

        // Both should present and verify successfully.
        let pres_v1 = cred_v1.present(&server_secret_params().get_public_params(), PRESENT_RAND);
        let pres_v2 = cred_v2.present(
            &server_secret_params().get_public_params(),
            [0xA4; RANDOMNESS_LEN],
        );
        pres_v1
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect("v1 presentation should verify");
        pres_v2
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect("v2 presentation should verify");
    }
}
