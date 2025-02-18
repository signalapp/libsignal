//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides GroupSendEndorsement and related types.
//!
//! GroupSendEndorsement is a MAC over:
//! - a ServiceId (computed from the ciphertexts on the group server at issuance, passed decrypted
//!   to the chat server for verification)
//! - an expiration timestamp, truncated to day granularity (chosen by the group server at issuance,
//!   passed publicly to the chat server for verification)

use std::fmt::Debug;

use derive_where::derive_where;
use partial_default::PartialDefault;
use poksho::ShoApi;
use rayon::iter::{IndexedParallelIterator as _, ParallelIterator as _};
use serde::{Deserialize, Serialize};
use zkcredential::attributes::Attribute as _;

use crate::common::array_utils;
use crate::common::serialization::ReservedByte;
use crate::groups::{GroupSecretParams, UuidCiphertext};
use crate::{
    crypto, RandomnessBytes, ServerPublicParams, ServerSecretParams, Timestamp,
    ZkGroupDeserializationFailure, ZkGroupVerificationFailure, SECONDS_PER_DAY,
};

const SECONDS_PER_HOUR: u64 = 60 * 60;

/// A key pair used to sign endorsements for a particular expiration.
///
/// These are intended to be cheaply cached -- it's not a problem to regenerate them, but they're
/// expected to be reused frequently enough that they're *worth* caching, given that they're only
/// rotated every 24 hours.
#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GroupSendDerivedKeyPair {
    reserved: ReservedByte,
    key_pair: zkcredential::endorsements::ServerDerivedKeyPair,
    expiration: Timestamp,
}

impl GroupSendDerivedKeyPair {
    /// Encapsulates the "tag info", or public attributes, of an endorsement, which is used to derive
    /// the appropriate signing key.
    fn tag_info(expiration: Timestamp) -> impl poksho::ShoApi + Clone {
        let mut sho = poksho::ShoHmacSha256::new(b"20240215_Signal_GroupSendEndorsement");
        sho.absorb_and_ratchet(&expiration.to_be_bytes());
        sho
    }

    /// Derives the appropriate key pair for the given expiration.
    pub fn for_expiration(expiration: Timestamp, params: &ServerSecretParams) -> Self {
        Self {
            reserved: ReservedByte::default(),
            key_pair: params
                .endorsement_key_pair
                .derive_key(Self::tag_info(expiration)),
            expiration,
        }
    }
}

/// The response issued from the group server, containing endorsements for all of a group's members.
///
/// The group server may cache this for a particular group as long as the group membership does not
/// change (being careful of expiration, of course). It is the same for every requesting member.
#[derive(Serialize, Deserialize, PartialDefault, Debug)]
pub struct GroupSendEndorsementsResponse {
    reserved: ReservedByte,
    endorsements: zkcredential::endorsements::EndorsementResponse,
    expiration: Timestamp,
}

impl GroupSendEndorsementsResponse {
    pub fn default_expiration(current_time: Timestamp) -> Timestamp {
        // Return the end of the next day, unless that's less than 25 hours away.
        // In that case, return the end of the following day.
        let current_time_in_seconds = current_time.epoch_seconds();
        let start_of_day = current_time_in_seconds - (current_time_in_seconds % SECONDS_PER_DAY);
        let mut expiration = start_of_day + 2 * SECONDS_PER_DAY;
        if (expiration - current_time_in_seconds) < SECONDS_PER_DAY + SECONDS_PER_HOUR {
            expiration += SECONDS_PER_DAY;
        }
        Timestamp::from_epoch_seconds(expiration)
    }

    /// Sorts `points` in *some* deterministic order based on the contents of each `RistrettoPoint`.
    ///
    /// Changing this order is a breaking change, since the issuing server and client must agree on
    /// it.
    ///
    /// The `usize` in each pair must be the original index of the point.
    fn sort_points(points: &mut [(usize, curve25519_dalek_signal::RistrettoPoint)]) {
        debug_assert!(points.iter().enumerate().all(|(i, (j, _))| i == *j));
        let sort_keys = curve25519_dalek_signal::RistrettoPoint::double_and_compress_batch(
            points.iter().map(|(_i, point)| point),
        );
        points.sort_unstable_by_key(|(i, _point)| sort_keys[*i].as_bytes());
    }

    /// Issues new endorsements, one for each of `member_ciphertexts`.
    ///
    /// `expiration` must match the expiration used to derive `key_pair`;
    pub fn issue(
        member_ciphertexts: impl IntoIterator<Item = UuidCiphertext>,
        key_pair: &GroupSendDerivedKeyPair,
        randomness: RandomnessBytes,
    ) -> Self {
        // Note: we could save some work here by pulling the single point we need out of the
        // serialized bytes, and operating directly on that. However, we'd have to remember to
        // update that if the serialization format ever changes.
        let mut points_to_sign: Vec<(usize, curve25519_dalek_signal::RistrettoPoint)> =
            member_ciphertexts
                .into_iter()
                .map(|ciphertext| ciphertext.ciphertext.as_points()[0])
                .enumerate()
                .collect();
        Self::sort_points(&mut points_to_sign);

        let endorsements = zkcredential::endorsements::EndorsementResponse::issue(
            points_to_sign.iter().map(|(_i, point)| *point),
            &key_pair.key_pair,
            randomness,
        );

        // We don't bother to "un-sort" the endorsements back to the original order of the points,
        // because clients don't keep track of that order anyway. Instead, we return the
        // endorsements in the sorted order we computed above.

        Self {
            reserved: ReservedByte::default(),
            endorsements,
            expiration: key_pair.expiration,
        }
    }

    /// Returns the expiration for all endorsements in the response.
    pub fn expiration(&self) -> Timestamp {
        self.expiration
    }

    /// Validates `self.expiration` against `now` and derives the appropriate signing key (using
    /// [`GroupSendDerivedKeyPair::tag_info`]).
    ///
    /// Note that if a client expects to receive endorsements from many different groups in one day
    /// it *could* be worth caching this, but the operation is pretty cheap compared to the rest of
    /// verifying responses, so we don't think it would make that much of a difference.
    fn derive_public_signing_key_from_expiration(
        &self,
        now: Timestamp,
        server_params: &ServerPublicParams,
    ) -> Result<zkcredential::endorsements::ServerDerivedPublicKey, ZkGroupVerificationFailure>
    {
        if !self.expiration.is_day_aligned() {
            // Reject credentials that don't expire on a day boundary,
            // because the server might be trying to fingerprint us.
            return Err(ZkGroupVerificationFailure);
        }
        let time_remaining_in_seconds = self.expiration.saturating_seconds_since(now);
        if time_remaining_in_seconds < 2 * SECONDS_PER_HOUR {
            // Reject credentials that expire in less than two hours,
            // including those that might expire in the past.
            // Two hours allows for clock skew plus incorrect summer time settings (+/- 1 hour).
            return Err(ZkGroupVerificationFailure);
        }
        if time_remaining_in_seconds > 7 * SECONDS_PER_DAY {
            // Reject credentials with expirations more than 7 days from now,
            // because the server might be trying to fingerprint us.
            return Err(ZkGroupVerificationFailure);
        }

        Ok(server_params
            .endorsement_public_key
            .derive_key(GroupSendDerivedKeyPair::tag_info(self.expiration)))
    }

    /// Same as [`Self::receive_with_service_ids`], but without parallelizing the zkgroup-specific
    /// parts of the operation.
    ///
    /// Only interesting for benchmarking. The zkcredential part of the operation may still be
    /// parallelized.
    pub fn receive_with_service_ids_single_threaded(
        self,
        user_ids: impl IntoIterator<Item = libsignal_core::ServiceId>,
        now: Timestamp,
        group_params: &GroupSecretParams,
        server_params: &ServerPublicParams,
    ) -> Result<Vec<ReceivedEndorsement>, ZkGroupVerificationFailure> {
        let derived_key = self.derive_public_signing_key_from_expiration(now, server_params)?;

        // The endorsements are sorted by the serialized *ciphertext* representations.
        // We have to compute the ciphertexts (expensive), but we can skip the second point (which
        // would be much more expensive).
        // We zip the results together with a set of indexes so we can un-sort the results later.
        let mut member_points: Vec<(usize, curve25519_dalek_signal::RistrettoPoint)> = user_ids
            .into_iter()
            .map(|user_id| {
                group_params.uid_enc_key_pair.a1 * crypto::uid_struct::UidStruct::calc_M1(user_id)
            })
            .enumerate()
            .collect();
        Self::sort_points(&mut member_points);

        let endorsements = self
            .endorsements
            .receive(member_points.iter().map(|(_i, point)| *point), &derived_key)
            .map_err(|_| ZkGroupVerificationFailure)?;

        Ok(array_utils::collect_permutation(
            endorsements
                .compressed
                .into_iter()
                .zip(endorsements.decompressed)
                .map(|(compressed, decompressed)| ReceivedEndorsement {
                    compressed: GroupSendEndorsement {
                        reserved: ReservedByte::default(),
                        endorsement: compressed,
                    },
                    decompressed: GroupSendEndorsement {
                        reserved: ReservedByte::default(),
                        endorsement: decompressed,
                    },
                })
                .zip(member_points.iter().map(|(i, _)| *i)),
        ))
    }

    /// Validates and returns the endorsements issued by the server.
    ///
    /// The result will be in the same order as `user_ids`. `user_ids` should contain the current
    /// user as well.
    ///
    /// If you already have the member ciphertexts for the group available,
    /// [`Self::receive_with_ciphertexts`] will be faster than this method.
    pub fn receive_with_service_ids<T>(
        self,
        user_ids: T,
        now: Timestamp,
        group_params: &GroupSecretParams,
        server_params: &ServerPublicParams,
    ) -> Result<Vec<ReceivedEndorsement>, ZkGroupVerificationFailure>
    where
        T: rayon::iter::IntoParallelIterator<
            Item = libsignal_core::ServiceId,
            Iter: rayon::iter::IndexedParallelIterator,
        >,
    {
        let derived_key = self.derive_public_signing_key_from_expiration(now, server_params)?;

        // The endorsements are sorted based on the *ciphertext* representations.
        // We have to compute the ciphertexts (expensive), but we can skip the second point (which
        // would be much more expensive).
        // We zip the results together with a set of indexes so we can un-sort the results later.
        let mut member_points: Vec<(usize, curve25519_dalek_signal::RistrettoPoint)> = user_ids
            .into_par_iter()
            .map(|user_id| {
                group_params.uid_enc_key_pair.a1 * crypto::uid_struct::UidStruct::calc_M1(user_id)
            })
            .enumerate()
            .collect();
        Self::sort_points(&mut member_points);

        let endorsements = self
            .endorsements
            .receive(member_points.iter().map(|(_i, point)| *point), &derived_key)
            .map_err(|_| ZkGroupVerificationFailure)?;

        Ok(array_utils::collect_permutation(
            endorsements
                .compressed
                .into_iter()
                .zip(endorsements.decompressed)
                .map(|(compressed, decompressed)| ReceivedEndorsement {
                    compressed: GroupSendEndorsement {
                        reserved: ReservedByte::default(),
                        endorsement: compressed,
                    },
                    decompressed: GroupSendEndorsement {
                        reserved: ReservedByte::default(),
                        endorsement: decompressed,
                    },
                })
                .zip(member_points.iter().map(|(i, _)| *i)),
        ))
    }

    /// Validates and returns the endorsements issued by the server.
    ///
    /// The result will be in the same order as `member_ciphertexts`. `member_ciphertexts` should
    /// contain the current user as well.
    ///
    /// If you don't already have the member ciphertexts for the group available,
    /// [`Self::receive_with_service_ids`] will be faster than computing them separately, using
    /// this method, and then throwing the ciphertexts away.
    pub fn receive_with_ciphertexts(
        self,
        member_ciphertexts: impl IntoIterator<Item = UuidCiphertext>,
        now: Timestamp,
        server_params: &ServerPublicParams,
    ) -> Result<Vec<ReceivedEndorsement>, ZkGroupVerificationFailure> {
        let derived_key = self.derive_public_signing_key_from_expiration(now, server_params)?;

        // Note: we could save some work here by pulling the single point we need out of the
        // serialized form of UuidCiphertext, and operating directly on that. However, we'd have to
        // remember to update that if the serialization format ever changes.
        let mut points_to_check: Vec<_> = member_ciphertexts
            .into_iter()
            .map(|ciphertext| ciphertext.ciphertext.as_points()[0])
            .enumerate()
            .collect();
        Self::sort_points(&mut points_to_check);

        let endorsements = self
            .endorsements
            .receive(
                points_to_check.iter().map(|(_i, point)| *point),
                &derived_key,
            )
            .map_err(|_| ZkGroupVerificationFailure)?;

        Ok(array_utils::collect_permutation(
            endorsements
                .compressed
                .into_iter()
                .zip(endorsements.decompressed)
                .map(|(compressed, decompressed)| ReceivedEndorsement {
                    compressed: GroupSendEndorsement {
                        reserved: ReservedByte::default(),
                        endorsement: compressed,
                    },
                    decompressed: GroupSendEndorsement {
                        reserved: ReservedByte::default(),
                        endorsement: decompressed,
                    },
                })
                .zip(points_to_check.iter().map(|(i, _)| *i)),
        ))
    }
}

/// A single endorsement, for one or multiple group members.
///
/// `Storage` is usually [`curve25519_dalek_signal::RistrettoPoint`], but the `receive` APIs on
/// [`GroupSendEndorsementsResponse`] produce "compressed" endorsements, since they are usually
/// immediately serialized.
#[derive(Serialize, Deserialize, PartialDefault, Clone, Copy)]
#[partial_default(bound = "Storage: curve25519_dalek_signal::traits::Identity")]
#[derive_where(PartialEq; Storage: subtle::ConstantTimeEq)]
pub struct GroupSendEndorsement<Storage = curve25519_dalek_signal::RistrettoPoint> {
    reserved: ReservedByte,
    endorsement: zkcredential::endorsements::Endorsement<Storage>,
}

impl Debug for GroupSendEndorsement<curve25519_dalek_signal::RistrettoPoint> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupSendEndorsement")
            .field("reserved", &self.reserved)
            .field("endorsement", &self.endorsement)
            .finish()
    }
}

impl Debug for GroupSendEndorsement<curve25519_dalek_signal::ristretto::CompressedRistretto> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupSendEndorsement")
            .field("reserved", &self.reserved)
            .field("endorsement", &self.endorsement)
            .finish()
    }
}

/// An endorsement as extracted from a [`GroupSendEndorsementsResponse`].
///
/// The `receive` process has to work with the endorsements in both compressed and decompressed
/// forms, so it might as well provide both to the caller. The compressed form is appropriate for
/// serialization (in fact it is essentially already serialized), while the decompressed form
/// supports further operations. Depending on what a client wants to do with the endorsements,
/// either or both could be useful.
///
/// The fields are public to support deconstruction one field at a time.
#[allow(missing_docs)]
#[derive(Clone, Copy, PartialDefault)]
pub struct ReceivedEndorsement {
    // Why does this zip together the compressed and decompressed endorsements, while zkcredential
    // uses two separate Vecs? Because the zkcredential processing has two Vecs already constructed,
    // and keeping them in that format can save on memory usage and copies (even though they *could*
    // be zipped together). zkgroup adds a version byte to every endorsement, which means the
    // existing memory allocation isn't sufficient anyway, and thus we're better off constructing a
    // single big Vec rather than two smaller ones, especially since we have to un-permute the
    // results. (It's close, though, only a 3-6% difference at the largest group sizes.)
    pub compressed: GroupSendEndorsement<curve25519_dalek_signal::ristretto::CompressedRistretto>,
    pub decompressed: GroupSendEndorsement,
}

impl GroupSendEndorsement<curve25519_dalek_signal::ristretto::CompressedRistretto> {
    /// Attempts to decompress the GroupSendEndorsement.
    ///
    /// Produces [`ZkGroupDeserializationFailure`] if the compressed storage isn't a valid
    /// representation of a point.
    ///
    /// Deserializing an `GroupSendEndorsement<RistrettoPoint>` is equivalent to deserializing an
    /// `GroupSendEndorsement<CompressedRistretto>` and then calling `decompress`.
    pub fn decompress(
        self,
    ) -> Result<
        GroupSendEndorsement<curve25519_dalek_signal::RistrettoPoint>,
        ZkGroupDeserializationFailure,
    > {
        Ok(GroupSendEndorsement {
            reserved: self.reserved,
            endorsement: self
                .endorsement
                .decompress()
                .map_err(|_| ZkGroupDeserializationFailure::new::<Self>())?,
        })
    }
}

impl GroupSendEndorsement<curve25519_dalek_signal::RistrettoPoint> {
    /// Compresses the GroupSendEndorsement for storage.
    ///
    /// Serializing an `GroupSendEndorsement<RistrettoPoint>` is equivalent to calling `compress` and
    /// serializing the resulting `GroupSendEndorsement<CompressedRistretto>`.
    pub fn compress(
        self,
    ) -> GroupSendEndorsement<curve25519_dalek_signal::ristretto::CompressedRistretto> {
        GroupSendEndorsement {
            reserved: self.reserved,
            endorsement: self.endorsement.compress(),
        }
    }
}

impl GroupSendEndorsement {
    /// Combines several endorsements into one.
    ///
    /// All endorsements must have been generated from the same issuance, or the resulting
    /// endorsement will not produce a valid token.
    ///
    /// This is a set-like operation: order does not matter.
    pub fn combine(
        endorsements: impl IntoIterator<Item = GroupSendEndorsement>,
    ) -> GroupSendEndorsement {
        let mut endorsements = endorsements.into_iter();
        let Some(mut result) = endorsements.next() else {
            // If we ever have multiple versions, it's not obvious which version to default to here,
            // since we normally require the versions to match when calling `combine` or `remove`.
            // But for now it's okay.
            return GroupSendEndorsement {
                reserved: ReservedByte::default(),
                endorsement: Default::default(),
            };
        };
        for next in endorsements {
            assert_eq!(
                result.reserved, next.reserved,
                "endorsements must all have the same version"
            );
            result.endorsement = result.endorsement.combine_with(&next.endorsement);
        }
        result
    }

    /// Removes endorsements from a previously-combined endorsement.
    ///
    /// Removing endorsements not present in `self` will result in an endorsement that will not
    /// produce a valid token.
    ///
    /// This is a set-like operation: order does not matter. Multiple endorsements can be removed by
    /// calling this method repeatedly, or by removing a single combined endorsement.
    pub fn remove(&self, unwanted_endorsements: &GroupSendEndorsement) -> GroupSendEndorsement {
        assert_eq!(
            self.reserved, unwanted_endorsements.reserved,
            "endorsements must have the same version"
        );
        GroupSendEndorsement {
            reserved: self.reserved,
            endorsement: self.endorsement.remove(&unwanted_endorsements.endorsement),
        }
    }

    /// Generates a bearer token from the endorsement.
    ///
    /// This can be cached by the client for repeatedly sending to the same recipient,
    /// but must be converted to a GroupSendFullToken before sending it to the server.
    pub fn to_token(&self, group_params: &GroupSecretParams) -> GroupSendToken {
        let client_key =
            zkcredential::endorsements::ClientDecryptionKey::for_first_point_of_attribute(
                &group_params.uid_enc_key_pair,
            );
        let raw_token = self.endorsement.to_token(&client_key);
        GroupSendToken {
            reserved: ReservedByte::default(),
            raw_token,
        }
    }
}

/// A token representing an endorsement.
///
/// This can be cached by the client for repeatedly sending to the same recipient,
/// but must be converted to a GroupSendFullToken before sending it to the server.
#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GroupSendToken {
    reserved: ReservedByte,
    raw_token: Box<[u8]>,
}

impl Debug for GroupSendToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupSendToken")
            .field("reserved", &self.reserved)
            .field("raw_token", &zkcredential::PrintAsHex(&*self.raw_token))
            .finish()
    }
}

impl GroupSendToken {
    /// Attaches the expiration to this token to create a GroupSendFullToken.
    ///
    /// If the incorrect expiration is used, the token will fail verification.
    pub fn into_full_token(self, expiration: Timestamp) -> GroupSendFullToken {
        GroupSendFullToken {
            reserved: self.reserved,
            raw_token: self.raw_token,
            expiration,
        }
    }
}

/// A token representing an endorsement, along with its expiration.
///
/// This will be serialized and sent to the chat server for verification.
#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GroupSendFullToken {
    reserved: ReservedByte,
    raw_token: Box<[u8]>,
    expiration: Timestamp,
}

impl Debug for GroupSendFullToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupSendFullToken")
            .field("reserved", &self.reserved)
            .field("raw_token", &zkcredential::PrintAsHex(&*self.raw_token))
            .field("expiration", &self.expiration)
            .finish()
    }
}

impl GroupSendFullToken {
    pub fn expiration(&self) -> Timestamp {
        self.expiration
    }

    /// Checks whether the token is (still) valid for sending to `user_ids` at `now` according to
    /// `key_pair`.
    pub fn verify(
        &self,
        user_ids: impl IntoIterator<Item = libsignal_core::ServiceId>,
        now: Timestamp,
        key_pair: &GroupSendDerivedKeyPair,
    ) -> Result<(), ZkGroupVerificationFailure> {
        if now > self.expiration {
            return Err(ZkGroupVerificationFailure);
        }
        assert_eq!(
            self.expiration, key_pair.expiration,
            "wrong key pair used for this token"
        );

        let user_id_sum: curve25519_dalek_signal::RistrettoPoint = user_ids
            .into_iter()
            .map(crypto::uid_struct::UidStruct::calc_M1)
            .sum();

        key_pair
            .key_pair
            .verify(&user_id_sum, &self.raw_token)
            .map_err(|_| ZkGroupVerificationFailure)
    }
}
