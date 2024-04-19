//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! A lightweight alternative to credentials based on [3HashSDHI][], similar to [PrivacyPass][].
//!
//! An _endorsement_ can be used instead of a full credential when there are no attributes hidden
//! from the verifying server, but exactly one attribute point needs to be hidden from the issuing
//! server. (If no points need to be hidden at all, use something simpler like [HMAC][]!)
//! Endorsement issuance uses the same sort of homogeneous elliptic-curve-based encryption as the
//! more powerful credential system, but verification is much cheaper, and the tokens generated from
//! endorsements can be reused for multiple requests. This differs from credentials, where every use
//! should have a new presentation to avoid being linkable with previous uses, but this isn't a
//! concern because all of the attributes that went into the endorsement are public to the verifying
//! server anyway.
//!
//! At a high level:
//!
//! 1. The client and issuing server agree on the set of public attributes ("tag info"), which the
//!    issuing server uses to derive a signing key.
//!
//! 2. The issuing server issues a list of endorsements for a list of hidden attributes (either
//!    blinded by the client as part of the initial request, or encrypted ahead of time). This is
//!    combined with a proof of validity in the form of a _response._
//!
//! 3. The client _receives_ the response, provides the same set of tag info, and validates the
//!    proof to extract the endorsements.
//!
//! 4. The client may optionally combine endorsements that have the same tag info, producing a new
//!    endorsement for a *set* of attributes.
//!
//! 5. The client generates a _token_ from the endorsement, first reversing the effect of the
//!    blinding or encryption, and then hashing the result.
//!
//! 6. The verifying server receives the token, along with all of the attributes. It recreates the
//!    token by issuing an endorsement for the now-revealed attribute point and then performing the
//!    same hashing operation. If the client-provided token matches the new one exactly, it is
//!    valid.
//!
//! The API in this module supports bulk issuance of endorsements, with a single proof of validity
//! that covers all endorsements issued together. Tokens can then be lazily generated on an
//! individual basis from the validated endorsements.
//!
//! Note that the "combine" operation (and its reverse, "remove") imply that the client has a
//! limited ability to synthesize endorsements that the issuing server never sees---for instance,
//! given an endorsement for attribute point P, the client can synthesize an endorsement for 2P, 3P,
//! -P, etc. Because of this, it's critical that the points used for the hidden attributes not be
//! algebraically related (a hash is recommended).
//!
//! This model can be extended to endorsements over *tuples* of attribute points as long as the
//! client uses only a single blinding key, but that has not been implemented here.
//!
//! [3HashSDHI]: https://eprint.iacr.org/2021/864
//! [PrivacyPass]: https://privacypass.github.io
//! [HMAC]: https://en.wikipedia.org/wiki/HMAC

use std::fmt::Debug;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use curve25519_dalek::{RistrettoPoint, Scalar};
use partial_default::PartialDefault;
use poksho::ShoApi;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use subtle::ConstantTimeEq;

use crate::sho::ShoExt;
use crate::{VerificationFailure, RANDOMNESS_LEN};

/// A server's secret key for issuing and verifying endorsements.
///
/// Endorsements are not directly issued using this key. Instead, a [`ServerDerivedKeyPair`] is
/// used, for domain separation, rotation, and additional authenticated info. One root key can be
/// used to issue many kinds of endorsements as long as they have distinct tag info.
#[derive(Clone, PartialDefault)]
pub struct ServerRootKeyPair {
    sk: Scalar,
    public: ServerRootPublicKey,
}

/// Serialize as a raw scalar.
impl<'de> Deserialize<'de> for ServerRootKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sk = Scalar::deserialize(deserializer)?;
        Ok(Self::from_raw(sk))
    }
}

/// Serialize as a raw scalar.
impl Serialize for ServerRootKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.sk.serialize(serializer)
    }
}

/// A *specific* secret key pair for issuing and verifying endorsements.
///
/// Derived from a [`ServerRootKeyPair`].
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct ServerDerivedKeyPair {
    sk_prime: Scalar,
    public: ServerDerivedPublicKey,
}

/// The public counterpart of [`ServerRootKeyPair`], used for verifying honest issuance of
/// endorsements.
///
/// Endorsements are not directly issued using a server's root key, so verifying issuance must be
/// done with a [`ServerDerivedPublicKey`].
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
#[serde(transparent)]
pub struct ServerRootPublicKey {
    PK: RistrettoPoint,
}

/// The public counterpart of [`ServerDerivedKeyPair`], used for verifying honest issuance of
/// endorsements.
///
/// Derived from a [`ServerRootPublicKey`].
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
#[serde(transparent)]
pub struct ServerDerivedPublicKey {
    PK_prime: RistrettoPoint,
}

/// A key used to transform endorsements of encrypted values to endorsements of decrypted values.
///
/// This can be used for getting endorsements of "blinded" points, encrypted purely for issuance of
/// the endorsement, or for getting endorsements of points encrypted using
/// [`crate::attributes::KeyPair`].
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
#[serde(transparent)]
pub struct ClientDecryptionKey {
    a_inv: Scalar,
}

impl ClientDecryptionKey {
    /// Produces a decryption key from a scalar used to blind arbitrary points.
    ///
    /// (In practice, this is a wrapper around [`Scalar::invert`].)
    pub fn from_blinding_scalar(scalar: Scalar) -> Self {
        Self {
            a_inv: scalar.invert(),
        }
    }

    /// Produces a decryption key from a key pair used to encrypt attributes.
    ///
    /// This key is appropriate for endorsements issued on the **first points** of encrypted
    /// attributes.
    pub fn for_first_point_of_attribute<D>(key_pair: &crate::attributes::KeyPair<D>) -> Self {
        Self::from_blinding_scalar(key_pair.a1)
    }
}

/// A set of endorsements issued by a server, along with the proof of their validity.
#[derive(Serialize, Deserialize, PartialDefault)]
#[cfg_attr(test, derive(Clone))]
pub struct EndorsementResponse {
    // Don't eagerly decompress these.
    R: Vec<CompressedRistretto>,
    proof: Vec<u8>,
}

impl Debug for EndorsementResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndorsementResponse")
            .field("R", &crate::PrintAsHex(&*self.R))
            .field("proof", &crate::PrintAsHex(&*self.proof))
            .finish()
    }
}

/// An endorsement of a particular hidden attribute point.
///
/// Endorsements are implicitly associated with both the point they were issued on, and the key used
/// to generate them; the key is in turn is derived from a known set of "tag info".
///
/// Endorsements may be persisted on the client, or may be eagerly converted to tokens using
/// [`to_token`][Self::to_token].
///
/// `Storage` should be [`RistrettoPoint`] or [`CompressedRistretto`].
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Endorsement<Storage = RistrettoPoint> {
    R: Storage,
}

impl Debug for Endorsement<RistrettoPoint> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.compress().fmt(f)
    }
}

impl Debug for Endorsement<CompressedRistretto> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endorsement")
            .field("R", &crate::PrintAsHex(self.R.as_bytes().as_slice()))
            .finish()
    }
}

impl<R: ConstantTimeEq> PartialEq for Endorsement<R> {
    fn eq(&self, other: &Endorsement<R>) -> bool {
        self.R.ct_eq(&other.R).into()
    }
}

impl Endorsement<CompressedRistretto> {
    /// Attempts to decompress the endorsement.
    ///
    /// Produces [`VerificationFailure`] if the compressed storage isn't a valid representation of a
    /// point.
    ///
    /// Deserializing an `Endorsement<RistrettoPoint>` is equivalent to deserializing an
    /// `Endorsement<CompressedRistretto>` and then calling `decompress`.
    pub fn decompress(self) -> Result<Endorsement<RistrettoPoint>, VerificationFailure> {
        match self.R.decompress() {
            Some(R) => Ok(Endorsement { R }),
            None => Err(VerificationFailure),
        }
    }
}

impl Endorsement<RistrettoPoint> {
    /// Compresses the endorsement for storage.
    ///
    /// Serializing an `Endorsement<RistrettoPoint>` is equivalent to calling `compress` and
    /// serializing the resulting `Endorsement<CompressedRistretto>`.
    pub fn compress(self) -> Endorsement<CompressedRistretto> {
        Endorsement {
            R: self.R.compress(),
        }
    }
}

/// The default endorsement is the "identity" of the `combine` and `remove` operations.
impl<Storage: curve25519_dalek::traits::Identity> Default for Endorsement<Storage> {
    fn default() -> Self {
        // This could actually just be a synthesized Default, because the Default for both
        // RistrettoPoint and CompressedRistretto is the identity point. But having an explicit impl
        // provides a place to attach a doc comment, and using the Identity trait makes it extra
        // clear what the expectation is.
        Self {
            R: Storage::identity(),
        }
    }
}

/// Endorsements as extracted from an [`EndorsementResponse`].
///
/// The [`receive`](EndorsementResponse::receive) process has to work with the endorsements in both
/// compressed and decompressed forms, so it might as well provide both to the caller. The
/// compressed form is appropriate for serialization (in fact it is essentially already serialized),
/// while the decompressed form supports further operations. Depending on what a client wants to do
/// with the endorsements, either or both could be useful.
///
/// The fields are public to support deconstruction one field at a time.
#[allow(missing_docs)]
#[derive(Clone)]
pub struct ReceivedEndorsements {
    pub compressed: Vec<Endorsement<CompressedRistretto>>,
    pub decompressed: Vec<Endorsement>,
}

/// Enough randomness that someone can't *guess* a correct token, but as small as possible to avoid
/// overhead!
const TOKEN_LEN: usize = 16;

impl ServerRootKeyPair {
    /// Derives a root key by hashing `randomness`.
    pub fn generate(randomness: [u8; RANDOMNESS_LEN]) -> Self {
        let mut sho = poksho::ShoHmacSha256::new(
            b"Signal_ZKCredential_Endorsements_ServerRootKeyPair_generate_20240207",
        );
        sho.absorb_and_ratchet(&randomness);
        Self::from_raw(sho.get_scalar())
    }

    /// Use an existing secret as a root key.
    pub fn from_raw(sk: Scalar) -> Self {
        Self {
            sk,
            public: ServerRootPublicKey {
                PK: RistrettoPoint::mul_base(&sk),
            },
        }
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> &ServerRootPublicKey {
        &self.public
    }

    /// Derives a specific key for issuing endorsements.
    ///
    /// **The `tag_info` should include a domain separation string** as well as any "public
    /// attributes" specific to the endorsements being issued. This is critical to ensure that
    /// endorsements for one kind of attribute cannot be repurposed as endorsements for another
    /// attribute. Note that the client and verifying server must be able to produce the same set of
    /// info.
    pub fn derive_key(&self, mut tag_info: impl ShoApi) -> ServerDerivedKeyPair {
        let t = tag_info.get_scalar();
        ServerDerivedKeyPair {
            sk_prime: (self.sk + t).invert(),
            public: self.public.derive_key_from_tag_scalar(&t),
        }
    }
}

impl ServerRootPublicKey {
    /// Use an existing point as a root public key.
    ///
    /// This is expected to be a point calculated as `sk * G`, where `sk` is the corresponding
    /// secret key scalar and `G` is the (standard) Ristretto basepoint.
    pub fn from_raw(PK: RistrettoPoint) -> Self {
        Self { PK }
    }

    /// Derives a specific public key used to issue endorsements according to `tag_info`.
    ///
    /// See [`ServerRootKeyPair::derive_key`] for a discussion of what belongs in `tag_info`;
    /// whatever the server does, the client must do the same.
    pub fn derive_key(&self, mut tag_info: impl ShoApi) -> ServerDerivedPublicKey {
        let t = tag_info.get_scalar();
        self.derive_key_from_tag_scalar(&t)
    }

    fn derive_key_from_tag_scalar(&self, t: &Scalar) -> ServerDerivedPublicKey {
        ServerDerivedPublicKey {
            PK_prime: self.PK + RistrettoPoint::mul_base(t),
        }
    }
}

impl EndorsementResponse {
    /// Issues an endorsement for every point in `hidden_attribute_points`, along with a batch proof
    /// of validity.
    ///
    /// The order of the points matters; the endorsements eventually received by the client will be
    /// in the same order.
    pub fn issue(
        hidden_attribute_points: impl IntoIterator<Item = RistrettoPoint>,
        private_key: &ServerDerivedKeyPair,
        randomness: [u8; RANDOMNESS_LEN],
    ) -> EndorsementResponse {
        let points = Vec::from_iter(hidden_attribute_points);
        let R = Vec::from_iter(
            points
                .iter()
                .map(|E_i| (private_key.sk_prime * E_i).compress()),
        );

        let weights_for_proof = Self::generate_weights_for_proof(&private_key.public, &points, &R);
        // We could use a vartime multiscalar mul here, but then it's *possible* some information
        // could be leaked about the points in question. Which should be blinded or encrypted
        // anyway, but even so. Until we're sure that this doesn't represent a risk, we'd rather
        // spend the extra CPU.
        let sum_E = points[0] + RistrettoPoint::multiscalar_mul(&weights_for_proof, &points[1..]);
        let sum_R = private_key.sk_prime * sum_E;

        let statement = EndorsementResponse::proof_statement();
        let mut point_args = poksho::PointArgs::new();
        point_args.add("weighted_sum(E)", sum_E);
        point_args.add("weighted_sum(R)", sum_R);
        point_args.add("PK_prime", private_key.public.PK_prime);
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("sk_prime", private_key.sk_prime);
        let proof = statement
            .prove(&scalar_args, &point_args, b"", &randomness)
            .unwrap();

        EndorsementResponse { R, proof }
    }

    fn proof_statement() -> poksho::Statement {
        let mut statement = poksho::Statement::new();
        // We use a weighted sum where the weights are generated by hashing the inputs (a "random
        // linear combination"), like PrivacyPass does. Checking every signature individually would
        // be prohibitively expensive, and a plain sum isn't strict enough. A weighted sum with
        // algebraically-unrelated elements leaves no room for the issuing server to not uphold its
        // end of the protocol, as long as the weights depend on both R and E. This is a Fiat-Shamir
        // transform of the approach described as "the RME-based common-exponent Schnorr protocol"
        // in Ryan Henry's "Efficient Zero-Knowledge Proofs and Applications" (2014) [1], originally
        // described by Kun Peng, Colin Boyd, and Ed Dawson in "Batch zero-knowledge proof and
        // verification and its applications" (2007).
        //
        // [1]: https://uwspace.uwaterloo.ca/handle/10012/8621
        statement.add("weighted_sum(R)", &[("sk_prime", "weighted_sum(E)")]);
        statement.add("G", &[("sk_prime", "PK_prime")]);
        statement
    }

    fn generate_weights_for_proof(
        public_key: &ServerDerivedPublicKey,
        E: &[RistrettoPoint],
        R: &[CompressedRistretto],
    ) -> Vec<Scalar> {
        debug_assert_eq!(E.len(), R.len());

        let mut gen = poksho::ShoHmacSha256::new(
            b"Signal_ZKCredential_Endorsements_EndorsementResponse_ProofWeights_20240207",
        );

        // Here and in the following steps we only need to absorb, since (1) all
        // inputs are equal length so we do not need ratcheting or standard
        // length prefixes to prevent different series of from producing the
        // same output (e.g. absorbing [1,2,3] then [4] gives same output as
        // absorbing [1,2] then [3,4]). Furthermore we do not need to use the
        // Sho's underlying secret until we squeeze out the random challenges.
        gen.absorb(public_key.PK_prime.compress().as_bytes());

        // It is more efficient to double and compress than to compress individually, and the doubled values
        // bind the prover to the E values just as much as compressing the E values directly would.
        let compressed_double_Es = RistrettoPoint::double_and_compress_batch(E);

        for E_i in compressed_double_Es {
            gen.absorb(E_i.as_bytes());
        }
        for R_i in R {
            gen.absorb(R_i.as_bytes());
        }
        gen.ratchet();

        // Deliberately generate scalars < 2^127 only, which we can multiply faster.
        // This still gives us 127-bit soundness according to Henry's analysis of RME (cited above).
        // (This is specifically "RME+", where the first scalar is hardcoded to be 1.)
        // We squeeze all of the scalar bytes at once so that we don't pay the cost of ratcheting
        // between each.
        const SMALL_SCALAR_BYTES: usize = 16;
        let randomness = gen.squeeze_and_ratchet((E.len() - 1) * SMALL_SCALAR_BYTES);
        randomness
            .chunks_exact(SMALL_SCALAR_BYTES)
            .map(|chunk| {
                let mut scalar_bytes = [0; 32];
                scalar_bytes[..16].copy_from_slice(chunk);
                scalar_bytes[15] &= 0b0111_1111;
                Scalar::from_bytes_mod_order(scalar_bytes)
            })
            .collect()
    }

    /// Validates and retrieves the endorsements stored in `self`.
    ///
    /// `hidden_attribute_points` should be the same points seen by the issuing server, i.e. blinded
    /// or encrypted points rather than "plaintexts", and must be in the same order. The return
    /// value will also be in this order.
    ///
    /// `server_public_key` must be derived using the same tag info as the key used to issue the
    /// endorsements, unsurprisingly.
    ///
    /// Produces an error if the proof fails to validate or if the number of points doesn't match
    /// the number of endorsements.
    pub fn receive(
        self,
        hidden_attribute_points: impl IntoIterator<Item = RistrettoPoint>,
        server_public_key: &ServerDerivedPublicKey,
    ) -> Result<ReceivedEndorsements, VerificationFailure> {
        let hidden_attribute_points = Vec::from_iter(hidden_attribute_points);
        if hidden_attribute_points.len() != self.R.len() {
            return Err(VerificationFailure);
        }

        let weights_for_proof =
            Self::generate_weights_for_proof(server_public_key, &hidden_attribute_points, &self.R);

        let decompress_or_default = |R_i: &CompressedRistretto| {
            // If any R_i fails to decompress, substituting RistrettoPoint::default() will make the
            // proof verification below fail.
            R_i.decompress().unwrap_or_default()
        };
        let R: Vec<RistrettoPoint> = {
            // cfg_if doesn't work as an expression, so we wrap it in an extra block.
            cfg_if::cfg_if! {
                if #[cfg(feature = "rayon")] {
                    use rayon::prelude::*;
                    self.R.par_iter().map(decompress_or_default).collect()
                } else {
                    self.R.iter().map(decompress_or_default).collect()
                }
            }
        };

        // It's okay for these to not be constant time because they are operating on points and
        // scalars known to both client and issuing server. For this to leak information, a third
        // party needs to observe how long the client spends on this receive operation, and at that
        // point they either have physical access to the device or are running instrumentation on
        // the device, both of which allow for much more intrusive attacks.
        let compute_sum_R =
            || R[0] + RistrettoPoint::vartime_multiscalar_mul(&weights_for_proof, &R[1..]);
        let compute_sum_E = || {
            hidden_attribute_points[0]
                + RistrettoPoint::vartime_multiscalar_mul(
                    &weights_for_proof,
                    &hidden_attribute_points[1..],
                )
        };
        let (sum_R, sum_E) = {
            // cfg_if doesn't work as an expression, so we wrap it in an extra block.
            cfg_if::cfg_if! {
                if #[cfg(feature = "rayon")] {
                    // We could split the sums into even more pieces, but this is mostly to benefit
                    // low-end devices, and low-end devices probably don't have that many cores
                    // available anyway.
                    rayon::join(compute_sum_R, compute_sum_E)
                } else {
                    (compute_sum_R(), compute_sum_E())
                }
            }
        };

        let statement = EndorsementResponse::proof_statement();
        let mut point_args = poksho::PointArgs::new();
        point_args.add("weighted_sum(E)", sum_E);
        point_args.add("weighted_sum(R)", sum_R);
        point_args.add("PK_prime", server_public_key.PK_prime);
        statement
            .verify_proof(&self.proof, &point_args, b"")
            .map_err(|_| VerificationFailure)?;

        Ok(ReceivedEndorsements {
            compressed: self
                .R
                .into_iter()
                .map(|R_i| Endorsement { R: R_i })
                .collect(),
            decompressed: R.into_iter().map(|R_i| Endorsement { R: R_i }).collect(),
        })
    }
}

impl Endorsement {
    /// Combines several endorsements into one.
    ///
    /// All endorsements must have been signed with the same server key, and they must be for points
    /// hidden with the same client key, or the resulting endorsement will not produce a valid
    /// token.
    ///
    /// This is a set-like operation: order does not matter, and the result is equivalent to the
    /// server issuing an endorsement of a sum of hidden attribute points. It is still an
    /// all-or-nothing endorsement; it does not allow one endorsement to be used for *any* point in
    /// the set, nor arbitrary subsets.
    ///
    /// This is equivalent to calling [`Self::combine_with`] repeatedly.
    pub fn combine(endorsements: impl IntoIterator<Item = Endorsement>) -> Endorsement {
        Endorsement {
            R: endorsements.into_iter().map(|each| each.R).sum(),
        }
    }

    /// Combines this endorsement with another.
    ///
    /// Both endorsements must have been signed with the same server key, and they must be for
    /// points hidden with the same client key, or the resulting endorsement will not produce a
    /// valid token.
    ///
    /// This is a set-like operation: order does not matter, and the result is equivalent to the
    /// server issuing an endorsement of a sum of hidden attribute points. It is still an
    /// all-or-nothing endorsement; it does not allow one endorsement to be used for *either* point
    /// in the set.
    ///
    /// This is equivalent to [`Self::combine`].
    pub fn combine_with(&self, other: &Endorsement) -> Endorsement {
        Endorsement {
            R: self.R + other.R,
        }
    }

    /// Creates an endorsement with `other` removed from `self`.
    ///
    /// This is useful when `self` represents a [combined](Self::combine) endorsement, but you want
    /// to remove some of the attributes from the original combined set.
    ///
    /// ```
    /// # use zkcredential::endorsements::Endorsement;
    /// # fn example(a: Endorsement, b: Endorsement, c: Endorsement) {
    /// let abc = Endorsement::combine([a, b, c]);
    /// let a_and_c = abc.remove(&b); // Equivalent to a.combine_with(c).
    /// # }
    /// ```
    ///
    /// Both endorsements must have been signed with the same server key, and they must be for
    /// points hidden with the same client key, or the resulting endorsement will not produce a
    /// valid token. Removing endorsements not present in `self` will also result in an endorsement
    /// that won't produce valid tokens.
    ///
    /// This is a set-like operation: order does not matter, and the result is equivalent to the
    /// server issuing an endorsement of a difference of hidden attribute points. Multiple
    /// endorsements can be removed by calling this method repeatedly, or by removing a single
    /// combined endorsement.
    pub fn remove(&self, other: &Endorsement) -> Endorsement {
        Endorsement {
            R: self.R - other.R,
        }
    }

    /// Generates a token from this endorsement, for sending to the verifying server.
    pub fn to_token(&self, client_key: &ClientDecryptionKey) -> Box<[u8]> {
        let P = self.R * client_key.a_inv;
        Self::to_token_raw(P)
    }

    fn to_token_raw(unblinded_endorsement: RistrettoPoint) -> Box<[u8]> {
        // Skip the Sho for this, we're hashing a single point into a single bitstring. We don't
        // need domain separation at this level because it should already be in the computation of
        // the endorsement point.
        //
        // Note that this deviates from 3HashSDHI, which hashes in the public and private attributes
        // as well. We get equivalent (actually stronger) security guarantees from the response
        // proof, which they have as an optional part of their system.
        sha2::Sha256::digest(unblinded_endorsement.compress().as_bytes()).as_slice()[..TOKEN_LEN]
            .into()
    }
}

impl ServerDerivedKeyPair {
    /// Verifies that a token is valid for `point` according to this key.
    ///
    /// If this key was derived using different tag info than the issuance of the endorsement that
    /// generated this token, the verification will fail.
    pub fn verify(&self, point: &RistrettoPoint, token: &[u8]) -> Result<(), VerificationFailure> {
        let P = self.sk_prime * point;
        let expected = Endorsement::to_token_raw(P);
        if token.ct_eq(&expected).into() {
            Ok(())
        } else {
            Err(VerificationFailure)
        }
    }
}

#[cfg(test)]
mod tests {
    use bincode::Options as _;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    use super::*;

    #[test]
    fn default_flow() {
        let mut input_sho = poksho::ShoSha256::new(b"test");
        let root_key = ServerRootKeyPair::generate([42; RANDOMNESS_LEN]);

        // Client

        let client_provided_points = [
            input_sho.get_point(),
            input_sho.get_point(),
            input_sho.get_point(),
        ];

        let client_raw_key = input_sho.get_scalar();
        let encrypted_points = client_provided_points.map(|p| client_raw_key * p);

        let mut info_sho = poksho::ShoHmacSha256::new(b"ExamplePass");
        info_sho.absorb_and_ratchet(b"today's date");

        let wrong_info_sho = input_sho;

        // Server

        let todays_key = root_key.derive_key(info_sho.clone());
        let response =
            EndorsementResponse::issue(encrypted_points, &todays_key, [43; RANDOMNESS_LEN]);

        // Client

        let decrypt_key = ClientDecryptionKey::from_blinding_scalar(client_raw_key);
        let todays_public_key = root_key.public.derive_key(info_sho.clone());
        let endorsements = response
            .clone()
            .receive(encrypted_points, &todays_public_key)
            .unwrap();
        assert_eq!(
            client_provided_points.len(),
            endorsements.decompressed.len()
        );
        assert_eq!(
            endorsements.decompressed.len(),
            endorsements.compressed.len()
        );

        for (decompressed, compressed) in endorsements
            .decompressed
            .iter()
            .zip(&endorsements.compressed)
        {
            assert_eq!(
                decompressed.compress().R.as_bytes(),
                compressed.R.as_bytes(),
            );
        }

        assert!(
            response
                .clone()
                .receive(encrypted_points.into_iter().skip(1), &todays_public_key,)
                .is_err(),
            "wrong number of points"
        );

        assert!(
            response
                .clone()
                .receive(client_provided_points, &todays_public_key,)
                .is_err(),
            "wrong points"
        );

        let wrong_public_key = root_key.public.derive_key(wrong_info_sho.clone());
        assert!(
            response
                .clone()
                .receive(encrypted_points, &wrong_public_key,)
                .is_err(),
            "wrong public key"
        );

        let tokens = endorsements
            .decompressed
            .into_iter()
            .map(|endorsement| endorsement.to_token(&decrypt_key));

        // Server

        let wrong_key = root_key.derive_key(wrong_info_sho.clone());

        for (token, point) in tokens.zip(client_provided_points) {
            todays_key.verify(&point, &token).unwrap();
            assert!(
                todays_key
                    .verify(&RISTRETTO_BASEPOINT_POINT, &token)
                    .is_err(),
                "wrong point"
            );
            assert!(wrong_key.verify(&point, &token).is_err(), "wrong key");
        }
    }

    #[test]
    fn combining_endorsements() {
        let mut input_sho = poksho::ShoSha256::new(b"test");
        let root_key = ServerRootKeyPair::generate([42; RANDOMNESS_LEN]);

        // Client

        let client_provided_points = [
            input_sho.get_point(),
            input_sho.get_point(),
            input_sho.get_point(),
        ];

        let client_raw_key = input_sho.get_scalar();
        let encrypted_points = client_provided_points.map(|p| client_raw_key * p);

        let mut info_sho = poksho::ShoHmacSha256::new(b"ExampleEndorsements");
        info_sho.absorb_and_ratchet(b"today's date");

        // Server

        let todays_key = root_key.derive_key(info_sho.clone());
        let issued_endorsements =
            EndorsementResponse::issue(encrypted_points, &todays_key, [43; RANDOMNESS_LEN]);

        // Client

        let decrypt_key = ClientDecryptionKey::from_blinding_scalar(client_raw_key);
        let todays_public_key = root_key.public.derive_key(info_sho.clone());

        let endorsements = issued_endorsements
            .receive(encrypted_points, &todays_public_key)
            .unwrap()
            .decompressed;
        let combined = Endorsement::combine(endorsements.iter().copied()).remove(&endorsements[1]);

        let token = combined.to_token(&decrypt_key);
        todays_key
            .verify(
                &(client_provided_points[0] + client_provided_points[2]),
                &token,
            )
            .unwrap();

        let manually_combined = endorsements[0].combine_with(&endorsements[2]);
        let manual_token = manually_combined.to_token(&decrypt_key);
        assert_eq!(&token, &manual_token);
    }

    #[test]
    fn serialized_representations() {
        #[track_caller]
        fn round_trip<T: Serialize + for<'a> Deserialize<'a> + PartialDefault>(
            value: &T,
            expected_len: usize,
        ) {
            let bincode_options = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_little_endian()
                .reject_trailing_bytes();

            let serialized = bincode_options.serialize(value).unwrap();
            assert_eq!(
                serialized.len(),
                expected_len,
                "wrong length for serialized {}",
                std::any::type_name::<T>()
            );

            let mut deserialized = T::partial_default();
            T::deserialize_in_place(
                &mut bincode::Deserializer::from_slice(&serialized, bincode_options),
                &mut deserialized,
            )
            .unwrap();

            let reserialized = bincode_options.serialize(&deserialized).unwrap();
            assert_eq!(&serialized, &reserialized);
        }

        const SCALAR_BYTE_COUNT: usize = 32;
        const POINT_BYTE_COUNT: usize = 32;

        let mut input_sho = poksho::ShoSha256::new(b"test");
        let root_key = ServerRootKeyPair::generate([42; RANDOMNESS_LEN]);
        round_trip(&root_key, SCALAR_BYTE_COUNT);
        round_trip(root_key.public_key(), POINT_BYTE_COUNT);

        // Client

        let client_provided_points = [
            input_sho.get_point(),
            input_sho.get_point(),
            input_sho.get_point(),
        ];

        let client_raw_key = input_sho.get_scalar();
        let encrypted_points = client_provided_points.map(|p| client_raw_key * p);

        let mut info_sho = poksho::ShoHmacSha256::new(b"ExampleEndorsements");
        info_sho.absorb_and_ratchet(b"today's date");

        // Server

        let todays_key = root_key.derive_key(info_sho.clone());
        round_trip(&todays_key, SCALAR_BYTE_COUNT + POINT_BYTE_COUNT);

        let response =
            EndorsementResponse::issue(encrypted_points, &todays_key, [43; RANDOMNESS_LEN]);
        // The exact size doesn't matter, just that it's not too big and doesn't change
        // unexpectedly.
        round_trip(&response, 176);

        // Client

        let decrypt_key = ClientDecryptionKey::from_blinding_scalar(client_raw_key);
        round_trip(&decrypt_key, SCALAR_BYTE_COUNT);

        let todays_public_key = root_key.public.derive_key(info_sho.clone());
        round_trip(&todays_public_key, POINT_BYTE_COUNT);

        let endorsements = response
            .clone()
            .receive(encrypted_points, &todays_public_key)
            .unwrap();
        assert_eq!(client_provided_points.len(), endorsements.compressed.len());
        round_trip(&endorsements.compressed[0], POINT_BYTE_COUNT);
        round_trip(&endorsements.decompressed[0], POINT_BYTE_COUNT);
    }

    #[test]
    fn default_is_identity() {
        assert_eq!(Endorsement::combine([]).R, Endorsement::default().R);

        let mut input_sho = poksho::ShoSha256::new(b"test");
        let root_key = ServerRootKeyPair::generate([42; RANDOMNESS_LEN]);

        // Client

        let client_provided_points = [
            input_sho.get_point(),
            input_sho.get_point(),
            input_sho.get_point(),
        ];

        let client_raw_key = input_sho.get_scalar();
        let encrypted_points = client_provided_points.map(|p| client_raw_key * p);

        let mut info_sho = poksho::ShoHmacSha256::new(b"ExamplePass");
        info_sho.absorb_and_ratchet(b"today's date");

        // Server

        let todays_key = root_key.derive_key(info_sho.clone());
        let response =
            EndorsementResponse::issue(encrypted_points, &todays_key, [43; RANDOMNESS_LEN]);

        // Client

        let todays_public_key = root_key.public.derive_key(info_sho.clone());
        let endorsements = response
            .clone()
            .receive(encrypted_points, &todays_public_key)
            .unwrap()
            .decompressed;
        assert_eq!(
            endorsements[0].remove(&endorsements[0]).R,
            Endorsement::default().R
        );
    }
}
