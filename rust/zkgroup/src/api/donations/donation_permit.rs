//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides DonationPermit and related types.
//!
//! DonationPermit is a single-use, unlinkable bearer token used to rate-limit access to
//! unauthenticated donation endpoints.
//!
//! DonationPermit is a MAC over:
//! - a random nonce (blinded by the client at issuance, revealed to the donation endpoint for
//!   verification)
//! - an expiration timestamp, truncated to day granularity (chosen by the issuing server, passed
//!   publicly to the donation endpoint for verification)

use std::fmt::Debug;
use std::num::NonZeroUsize;

use curve25519_dalek_signal::{RistrettoPoint, Scalar};
use partial_default::PartialDefault;
use poksho::ShoApi;
use poksho::shoapi::ShoApiExt as _;
use serde::{Deserialize, Serialize};
use zkcredential::sho::ShoExt as _;

use crate::api::endorsement_expiration;
use crate::common::serialization::ReservedByte;
use crate::{RandomnessBytes, Timestamp, ZkGroupVerificationFailure};

/// The length of a permit nonce, in bytes.
///
/// A full 256 bits of randomness: nonces are the spent-set key, so we want ample collision
/// headroom at donation volume and zero chance of a guess. The nonce is cheap (sent once, at
/// redemption), so there's no reason to economize here.
///
/// This is used as the `spend_id` to enforce single use. Keep this in mind if
/// considering making it smaller.
const NONCE_LEN: usize = 32;

type NonceBytes = [u8; NONCE_LEN];

/// Domain-separates the hash-to-point used to turn a nonce into a verifiable attribute point.
fn nonce_to_point(nonce: &NonceBytes) -> RistrettoPoint {
    let mut sho =
        poksho::ShoHmacSha256::new(b"20260611_Signal_DonationPermitEndorsement_NonceToPoint");
    sho.absorb_and_ratchet(nonce);
    sho.get_point()
}

/// A key pair used to issue and verify donation permits for a particular expiration.
///
/// These are intended to be cheaply cached; the redeeming server only needs the derived key pair,
/// never the root secret.
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct DonationPermitDerivedKeyPair {
    reserved: ReservedByte,
    key_pair: zkcredential::endorsements::ServerDerivedKeyPair,
    expiration: Timestamp,
}

impl DonationPermitDerivedKeyPair {
    /// Encapsulates the "tag info", or public attributes, of a permit, which is used to derive the
    /// appropriate signing key.
    fn tag_info(expiration: Timestamp) -> impl ShoApi + Clone {
        let mut sho = poksho::ShoHmacSha256::new(b"20260611_Signal_DonationPermitEndorsement");
        sho.absorb_and_ratchet(&expiration.to_be_bytes());
        sho
    }

    /// Derives the appropriate key pair for the given expiration.
    pub fn for_expiration(
        expiration: Timestamp,
        root: impl AsRef<zkcredential::endorsements::ServerRootKeyPair>,
    ) -> Self {
        Self {
            reserved: ReservedByte::default(),
            key_pair: root.as_ref().derive_key(Self::tag_info(expiration)),
            expiration,
        }
    }

    /// The expiration this key pair was derived for.
    pub fn expiration(&self) -> Timestamp {
        self.expiration
    }
}

/// The wire message a client sends to the issuing (chat) server to request permits.
///
/// It carries one blinded attribute point per requested permit. The server learns nothing about
/// the underlying nonces, and does not need a proof from the client: a malformed point only wastes
/// the client's own rate-limit allowance, because no nonce preimage will ever hash to it.
#[derive(Clone, Serialize, Deserialize, PartialDefault, Debug)]
pub struct DonationPermitRequest {
    reserved: ReservedByte,
    // Stored decompressed so that deserialization validates the point encodings up front.
    blinded_points: Vec<RistrettoPoint>,
}

impl DonationPermitRequest {
    /// The number of permits requested.
    pub fn len(&self) -> usize {
        self.blinded_points.len()
    }

    /// Whether the request asks for zero permits (which the server should reject).
    pub fn is_empty(&self) -> bool {
        self.blinded_points.is_empty()
    }
}

/// Client-retained state for an in-flight permit request.
///
/// This holds the per-permit secrets (nonces and blinding scalars) that the client needs to unblind
/// the eventual [`DonationPermitResponse`]. It must be persisted between sending the
/// [`request`][Self::request] and calling [`receive`][Self::receive].
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct DonationPermitRequestContext {
    reserved: ReservedByte,
    nonces: Vec<NonceBytes>,
    blinding_scalars: Vec<Scalar>,
    blinded_points: Vec<RistrettoPoint>,
}

impl DonationPermitRequestContext {
    /// Samples `count` fresh permits' worth of nonces and blinding scalars from `randomness`.
    ///
    /// Each nonce gets an independent blinding scalar, so every eventual permit is
    /// information-theoretically independent of issuance and of its siblings.
    pub fn new(count: NonZeroUsize, randomness: RandomnessBytes) -> Self {
        let count = count.get();
        let mut sho =
            poksho::ShoHmacSha256::new(b"20260611_Signal_DonationPermitEndorsement_RequestContext");
        sho.absorb_and_ratchet(&randomness);

        let mut nonces = Vec::with_capacity(count);
        let mut blinding_scalars = Vec::with_capacity(count);
        let mut blinded_points = Vec::with_capacity(count);
        for _ in 0..count {
            let nonce: NonceBytes = sho.squeeze_and_ratchet_as_array();
            let blinding_scalar = sho.get_scalar();
            let blinded_point = blinding_scalar * nonce_to_point(&nonce);
            nonces.push(nonce);
            blinding_scalars.push(blinding_scalar);
            blinded_points.push(blinded_point);
        }

        Self {
            reserved: ReservedByte::default(),
            nonces,
            blinding_scalars,
            blinded_points,
        }
    }

    /// The wire request to send to the issuing server.
    pub fn request(&self) -> DonationPermitRequest {
        DonationPermitRequest {
            reserved: ReservedByte::default(),
            blinded_points: self.blinded_points.clone(),
        }
    }

    /// Validates the issuer's response and extracts the redeemable permits.
    ///
    /// `now` is used to validate the response's expiration window. `root_public_key` must be the
    /// audited, client-pinned public key; verifying the issuance proof against it is what prevents
    /// the issuing server from tagging this client with a per-client key.
    ///
    /// The returned permits are in the same order as the nonces in this context.
    pub fn receive(
        self,
        response: DonationPermitResponse,
        root_public_key: impl AsRef<zkcredential::endorsements::ServerRootPublicKey>,
        now: Timestamp,
    ) -> Result<Vec<DonationPermit>, ZkGroupVerificationFailure> {
        let derived_key =
            response.derive_public_signing_key_from_expiration(now, root_public_key)?;

        let endorsements = response
            .endorsements
            .receive(self.blinded_points.iter().copied(), &derived_key)
            .map_err(|_| ZkGroupVerificationFailure)?;

        let permits = endorsements
            .decompressed
            .into_iter()
            .zip(&self.nonces)
            .zip(&self.blinding_scalars)
            .map(|((endorsement, nonce), blinding_scalar)| {
                let client_key =
                    zkcredential::endorsements::ClientDecryptionKey::from_blinding_scalar(
                        *blinding_scalar,
                    );
                DonationPermit {
                    reserved: ReservedByte::default(),
                    expiration: response.expiration,
                    nonce: *nonce,
                    raw_token: endorsement.to_token(&client_key),
                }
            })
            .collect();
        Ok(permits)
    }
}

/// The issuing server's response: a batch of endorsements with a proof of honest issuance.
///
/// Mirrors the structure of the underlying [`zkcredential::endorsements::EndorsementResponse`],
/// plus the expiration the key was derived for.
#[derive(Clone, Serialize, Deserialize, PartialDefault, Debug)]
pub struct DonationPermitResponse {
    reserved: ReservedByte,
    endorsements: zkcredential::endorsements::EndorsementResponse,
    expiration: Timestamp,
}

impl DonationPermitResponse {
    pub fn default_expiration(current_time: Timestamp) -> Timestamp {
        endorsement_expiration::default_expiration(current_time)
    }

    /// Blindly issues an endorsement for each blinded point in `request`.
    ///
    /// The issuing server does not (and cannot) inspect the underlying nonces. Per-account rate
    /// limiting is a policy decision made by the caller before issuing.
    pub fn issue(
        request: DonationPermitRequest,
        key_pair: &DonationPermitDerivedKeyPair,
        randomness: RandomnessBytes,
    ) -> Self {
        let endorsements = zkcredential::endorsements::EndorsementResponse::issue(
            request.blinded_points,
            &key_pair.key_pair,
            randomness,
        );
        Self {
            reserved: ReservedByte::default(),
            endorsements,
            expiration: key_pair.expiration,
        }
    }

    /// The expiration shared by all permits in this response.
    pub fn expiration(&self) -> Timestamp {
        self.expiration
    }

    /// Validates `self.expiration` against `now` and derives the appropriate signing key (using
    /// [`DonationPermitDerivedKeyPair::tag_info`]).
    fn derive_public_signing_key_from_expiration(
        &self,
        now: Timestamp,
        root_public_key: impl AsRef<zkcredential::endorsements::ServerRootPublicKey>,
    ) -> Result<zkcredential::endorsements::ServerDerivedPublicKey, ZkGroupVerificationFailure>
    {
        endorsement_expiration::validate_expiration(self.expiration, now)?;

        Ok(root_public_key
            .as_ref()
            .derive_key(DonationPermitDerivedKeyPair::tag_info(self.expiration)))
    }
}

/// A single redeemable donation permit.
///
/// This is the value sent, over an unauthenticated connection, to a donation endpoint. It is a
/// *bearer* token: it does not bind to any particular request, so it must be transmitted over a
/// confidential channel (e.g. TLS).
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct DonationPermit {
    reserved: ReservedByte,
    expiration: Timestamp,
    nonce: NonceBytes,
    raw_token: Box<[u8]>,
}

impl Debug for DonationPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            reserved,
            expiration,
            nonce,
            raw_token,
        } = self;
        f.debug_struct("DonationPermit")
            .field("reserved", reserved)
            .field("expiration", expiration)
            .field("nonce", &zkcredential::PrintAsHex(nonce.as_slice()))
            .field("raw_token", &zkcredential::PrintAsHex(&**raw_token))
            .finish()
    }
}

impl DonationPermit {
    /// The expiration after which this permit can no longer be redeemed.
    pub fn expiration(&self) -> Timestamp {
        self.expiration
    }

    /// The key a redeeming server should use to detect double-spends: the permit's nonce.
    ///
    /// The nonce uniquely identifies the permit and cannot be altered without invalidating the
    /// token (verification recomputes the attribute point from it), so a replayed permit produces
    /// the same key. The redeeming server must record this (scoped to
    /// [`expiration`][Self::expiration]) and reject any permit whose key it has already seen.
    pub fn spend_id(&self) -> &[u8] {
        &self.nonce
    }

    /// Verifies that this permit was honestly issued for the current day under `key_pair`.
    ///
    /// **This does not enforce single use.** The caller must additionally check
    /// [`spend_id`][Self::spend_id] against its spent set and record it on success.
    pub fn verify(
        &self,
        now: Timestamp,
        key_pair: &DonationPermitDerivedKeyPair,
    ) -> Result<(), ZkGroupVerificationFailure> {
        endorsement_expiration::validate_expiration(self.expiration, now)?;
        assert_eq!(
            self.expiration, key_pair.expiration,
            "wrong key pair used for this token"
        );

        let point = nonce_to_point(&self.nonce);
        key_pair
            .key_pair
            .verify(&point, &self.raw_token)
            .map_err(|_| ZkGroupVerificationFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerPublicParams, ServerSecretParams};

    const NOW: Timestamp = Timestamp::from_epoch_seconds(1_600_000_000);

    fn server_params() -> (ServerSecretParams, ServerPublicParams) {
        let secret = ServerSecretParams::generate([0x42; 32]);
        let public = secret.get_public_params();
        (secret, public)
    }

    /// Issues and receives a single valid permit for `NOW`, returning it alongside the matching
    /// derived key pair (its expiration is reachable via [`DonationPermitDerivedKeyPair::expiration`]).
    fn issue_one_permit(
        request_seed: RandomnessBytes,
        issue_seed: RandomnessBytes,
    ) -> (DonationPermit, DonationPermitDerivedKeyPair) {
        let (secret, public) = server_params();
        let expiration = DonationPermitResponse::default_expiration(NOW);
        let key_pair = DonationPermitDerivedKeyPair::for_expiration(expiration, &secret);

        let context = DonationPermitRequestContext::new(NonZeroUsize::MIN, request_seed);
        let response = DonationPermitResponse::issue(context.request(), &key_pair, issue_seed);
        let permit = context
            .receive(response, &public, NOW)
            .expect("valid response")
            .pop()
            .expect("one permit");
        (permit, key_pair)
    }

    #[test]
    fn default_flow() {
        let (secret, public) = server_params();
        let expiration = DonationPermitResponse::default_expiration(NOW);
        let key_pair = DonationPermitDerivedKeyPair::for_expiration(expiration, &secret);

        // Client: request three permits.
        let context = DonationPermitRequestContext::new(NonZeroUsize::new(3).unwrap(), [0x42; 32]);
        let request = context.request();
        assert_eq!(request.len(), 3);

        // Issuing server: blindly issue.
        let response = DonationPermitResponse::issue(request, &key_pair, [0x37; 32]);
        assert_eq!(response.expiration(), expiration);

        // Client: receive and unblind.
        let permits = context
            .receive(response, &public, NOW)
            .expect("valid response");
        assert_eq!(permits.len(), 3);

        // Redeeming server: every permit verifies under the day's key.
        for permit in &permits {
            permit.verify(NOW, &key_pair).expect("valid permit");
        }

        // Spend IDs are distinct across permits.
        let mut spent: Vec<&[u8]> = permits.iter().map(|p| p.spend_id()).collect();
        spent.dedup();
        assert_eq!(spent.len(), 3, "spend IDs should be distinct");
    }

    #[test]
    fn wrong_key_fails() {
        let (permit, key_pair) = issue_one_permit([0x86; 32], [0x67; 32]);

        let other_secret = ServerSecretParams::generate([0xAF; 32]);
        let wrong_key =
            DonationPermitDerivedKeyPair::for_expiration(key_pair.expiration(), &other_secret);
        permit.verify(NOW, &wrong_key).expect_err("wrong key");
    }

    #[test]
    fn tampered_nonce_fails() {
        let (mut permit, key_pair) = issue_one_permit([0x41; 32], [0x43; 32]);

        permit.nonce[0] ^= 0xff;
        permit.verify(NOW, &key_pair).expect_err("tampered nonce");
    }

    #[test]
    fn expired_permit_fails() {
        let (permit, key_pair) = issue_one_permit([0x14; 32], [0x28; 32]);

        let after_expiry = Timestamp::from_epoch_seconds(key_pair.expiration().epoch_seconds() + 1);
        permit
            .verify(after_expiry, &key_pair)
            .expect_err("expired permit");
    }

    #[test]
    fn non_dayaligned_expiration_rejected() {
        let (secret, public) = server_params();
        // A non-day-aligned expiration must be rejected by the client on receive.
        let expiration = Timestamp::from_epoch_seconds(
            DonationPermitResponse::default_expiration(NOW).epoch_seconds() + 1,
        );
        let key_pair = DonationPermitDerivedKeyPair::for_expiration(expiration, &secret);

        let context = DonationPermitRequestContext::new(NonZeroUsize::MIN, [0x01; 32]);
        let response = DonationPermitResponse::issue(context.request(), &key_pair, [0x02; 32]);
        context
            .receive(response, &public, NOW)
            .expect_err("non-day-aligned expiration");
    }
}
