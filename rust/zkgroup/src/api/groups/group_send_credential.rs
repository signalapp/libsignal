//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides GroupSendCredential and related types.
//!
//! GroupSendCredential is a MAC over:
//! - a set of ACIs (computed from the ciphertexts on the group server at issuance, passed decrypted to the chat server for verification)
//! - a timestamp, truncated to day granularity (chosen by the group server at issuance, passed publicly to the chat server for verification)

use std::marker::PhantomData;

use derive_where::derive_where;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use zkcredential::attributes::{Attribute, Domain};

use crate::common::simple_types::*;
use crate::crypto::uid_encryption;
use crate::crypto::uid_struct::UidStruct;
use crate::groups::{GroupSecretParams, UuidCiphertext};
use crate::{ServerPublicParams, ServerSecretParams, ZkGroupVerificationFailure, SECONDS_PER_DAY};

const CREDENTIAL_LABEL: &[u8] = b"20231011_Signal_GroupSendCredential";
const SECONDS_PER_HOUR: u64 = 60 * 60;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[derive_where(Default)]
struct UserIdSet<T> {
    points: [curve25519_dalek::RistrettoPoint; 2],
    kind: PhantomData<T>,
}

impl<T: Attribute + Eq> UserIdSet<T> {
    fn from_user_ids_omitting_requester(
        user_ids: impl IntoIterator<Item = T>,
        requester: &T,
    ) -> Result<Self, ZkGroupVerificationFailure> {
        let mut user_id_set = UserIdSet::default();
        let mut has_seen_requester = false;
        for ciphertext in user_ids {
            if &ciphertext == requester {
                if has_seen_requester {
                    // Requester is present multiple times?
                    return Err(ZkGroupVerificationFailure);
                }
                has_seen_requester = true;
                continue;
            }

            let points = ciphertext.as_points();
            user_id_set.points[0] += points[0];
            user_id_set.points[1] += points[1];
        }

        if !has_seen_requester {
            // Requester is not in group.
            return Err(ZkGroupVerificationFailure);
        }

        Ok(user_id_set)
    }

    fn from_user_ids(user_ids: impl IntoIterator<Item = T>) -> Self {
        user_ids
            .into_iter()
            .fold(Default::default(), |mut acc, next| {
                let points = next.as_points();
                acc.points[0] += points[0];
                acc.points[1] += points[1];
                acc
            })
    }
}

impl<T> zkcredential::attributes::Attribute for UserIdSet<T> {
    fn as_points(&self) -> [curve25519_dalek::RistrettoPoint; 2] {
        self.points
    }
}

impl<T> From<zkcredential::attributes::Ciphertext<UserIdSet<T::Attribute>>>
    for UserIdSet<zkcredential::attributes::Ciphertext<T>>
where
    T: zkcredential::attributes::Domain,
{
    fn from(value: zkcredential::attributes::Ciphertext<UserIdSet<T::Attribute>>) -> Self {
        Self {
            points: value.as_points(),
            kind: PhantomData,
        }
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GroupSendCredentialResponse {
    reserved: ReservedBytes,
    proof: zkcredential::issuance::IssuanceProof,
    user_id_set: UserIdSet<uid_encryption::Ciphertext>,
    expiration: Timestamp,
}

impl GroupSendCredentialResponse {
    pub fn default_expiration(current_time_in_seconds: Timestamp) -> Timestamp {
        // Return the end of the current day, unless that's less than two hours away.
        // In that case, return the end of the following day.
        let start_of_day = current_time_in_seconds - (current_time_in_seconds % SECONDS_PER_DAY);
        let mut expiration = start_of_day + SECONDS_PER_DAY;
        if (expiration - current_time_in_seconds) < 2 * SECONDS_PER_HOUR {
            expiration += SECONDS_PER_DAY;
        }
        expiration
    }

    pub fn issue_credential(
        user_id_ciphertexts: impl IntoIterator<Item = UuidCiphertext>,
        requester: &UuidCiphertext,
        expiration: Timestamp,
        params: &ServerSecretParams,
        randomness: RandomnessBytes,
    ) -> Result<GroupSendCredentialResponse, ZkGroupVerificationFailure> {
        let user_id_set = UserIdSet::from_user_ids_omitting_requester(
            user_id_ciphertexts.into_iter().map(|c| c.ciphertext),
            &requester.ciphertext,
        )?;

        let proof = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&user_id_set)
            .add_public_attribute(&expiration)
            .issue(&params.generic_credential_key_pair, randomness);
        Ok(Self {
            reserved: [0],
            proof,
            user_id_set,
            expiration,
        })
    }

    pub fn receive(
        self,
        params: &ServerPublicParams,
        group_params: &GroupSecretParams,
        user_ids: impl IntoIterator<Item = libsignal_core::ServiceId>,
        requester: libsignal_core::ServiceId,
        now: Timestamp,
    ) -> Result<GroupSendCredential, ZkGroupVerificationFailure> {
        if self.expiration % SECONDS_PER_DAY != 0 {
            return Err(ZkGroupVerificationFailure);
        }
        if self.expiration.saturating_sub(now) > 7 * SECONDS_PER_DAY {
            // Reject credentials with expirations more than 7 days from now,
            // because the server might be trying to fingerprint us.
            return Err(ZkGroupVerificationFailure);
        }

        let user_id_set = UserIdSet::from_user_ids_omitting_requester(
            user_ids.into_iter().map(UidStruct::from_service_id),
            &UidStruct::from_service_id(requester),
        )?;
        let user_id_set_ciphertext = group_params
            .uid_enc_key_pair
            .encrypt_arbitrary_attribute(&user_id_set);

        let raw_credential = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&user_id_set_ciphertext)
            .add_public_attribute(&self.expiration)
            .verify(&params.generic_credential_public_key, self.proof)
            .map_err(|_| ZkGroupVerificationFailure)?;

        let encryption_key_pair =
            zkcredential::attributes::KeyPair::inverse_of(&group_params.uid_enc_key_pair);

        Ok(GroupSendCredential {
            reserved: [0],
            credential: raw_credential,
            user_id_set_ciphertext: user_id_set_ciphertext.into(),
            expiration: self.expiration,
            encryption_key_pair,
        })
    }

    pub fn receive_with_ciphertexts(
        self,
        params: &ServerPublicParams,
        group_params: &GroupSecretParams,
        user_id_ciphertexts: impl IntoIterator<Item = UuidCiphertext>,
        requester: &UuidCiphertext,
        now: Timestamp,
    ) -> Result<GroupSendCredential, ZkGroupVerificationFailure> {
        if self.expiration % SECONDS_PER_DAY != 0 {
            return Err(ZkGroupVerificationFailure);
        }
        if self.expiration.saturating_sub(now) > 7 * SECONDS_PER_DAY {
            // Reject credentials with expirations more than 7 days from now,
            // because the server might be trying to fingerprint us.
            return Err(ZkGroupVerificationFailure);
        }

        let user_id_set_ciphertext = UserIdSet::from_user_ids_omitting_requester(
            user_id_ciphertexts.into_iter().map(|c| c.ciphertext),
            &requester.ciphertext,
        )?;

        let raw_credential = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&user_id_set_ciphertext)
            .add_public_attribute(&self.expiration)
            .verify(&params.generic_credential_public_key, self.proof)
            .map_err(|_| ZkGroupVerificationFailure)?;

        let encryption_key_pair =
            zkcredential::attributes::KeyPair::inverse_of(&group_params.uid_enc_key_pair);

        Ok(GroupSendCredential {
            reserved: [0],
            credential: raw_credential,
            user_id_set_ciphertext,
            expiration: self.expiration,
            encryption_key_pair,
        })
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GroupSendCredential {
    reserved: ReservedBytes,
    credential: zkcredential::credentials::Credential,
    user_id_set_ciphertext: UserIdSet<crate::crypto::uid_encryption::Ciphertext>,
    expiration: Timestamp,
    // Additionally includes this because we'd need to recompute it with every message otherwise.
    encryption_key_pair: zkcredential::attributes::KeyPair<InverseUidEncryptionDomain>,
}

impl GroupSendCredential {
    pub fn present(
        &self,
        server_params: &ServerPublicParams,
        randomness: RandomnessBytes,
    ) -> GroupSendCredentialPresentation {
        let proof = zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute_without_verified_key(
                &self.user_id_set_ciphertext,
                &self.encryption_key_pair,
            )
            .present(
                &server_params.generic_credential_public_key,
                &self.credential,
                randomness,
            );
        GroupSendCredentialPresentation {
            reserved: [0],
            proof,
            expiration: self.expiration,
        }
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GroupSendCredentialPresentation {
    reserved: ReservedBytes,
    proof: zkcredential::presentation::PresentationProof,
    // Does not include the set of user IDs because that's in the message payload
    expiration: Timestamp,
}

impl GroupSendCredentialPresentation {
    pub fn verify(
        &self,
        user_ids: impl IntoIterator<Item = libsignal_core::ServiceId>,
        current_time_in_seconds: Timestamp,
        server_params: &ServerSecretParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        if current_time_in_seconds > self.expiration {
            return Err(ZkGroupVerificationFailure);
        }

        let user_id_set =
            UserIdSet::from_user_ids(user_ids.into_iter().map(UidStruct::from_service_id));

        zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
            .add_attribute_without_verified_key(&user_id_set, InverseUidEncryptionDomain::ID)
            .add_public_attribute(&self.expiration)
            .verify(&server_params.generic_credential_key_pair, &self.proof)
            .map_err(|_| ZkGroupVerificationFailure)
    }
}

struct InverseUidEncryptionDomain;
impl zkcredential::attributes::Domain for InverseUidEncryptionDomain {
    type Attribute = UserIdSet<uid_encryption::Ciphertext>;
    const ID: &'static str = "Signal_GroupSendCredential_InverseUidEncryptionDomain_20231011";

    fn G_a() -> [curve25519_dalek::RistrettoPoint; 2] {
        static STORAGE: std::sync::OnceLock<[curve25519_dalek::RistrettoPoint; 2]> =
            std::sync::OnceLock::new();
        *zkcredential::attributes::derive_default_generator_points::<Self>(&STORAGE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_ALIGNED_TIMESTAMP: Timestamp = 1681344000; // 2023-04-13 00:00:00 UTC

    #[test]
    fn test_default_expiration() {
        assert_eq!(
            DAY_ALIGNED_TIMESTAMP + SECONDS_PER_DAY,
            GroupSendCredentialResponse::default_expiration(DAY_ALIGNED_TIMESTAMP)
        );
        assert_eq!(
            DAY_ALIGNED_TIMESTAMP + SECONDS_PER_DAY,
            GroupSendCredentialResponse::default_expiration(DAY_ALIGNED_TIMESTAMP + 1)
        );
        assert_eq!(
            DAY_ALIGNED_TIMESTAMP + SECONDS_PER_DAY,
            GroupSendCredentialResponse::default_expiration(
                DAY_ALIGNED_TIMESTAMP + SECONDS_PER_HOUR
            )
        );
        assert_eq!(
            DAY_ALIGNED_TIMESTAMP + SECONDS_PER_DAY,
            GroupSendCredentialResponse::default_expiration(
                DAY_ALIGNED_TIMESTAMP + 22 * SECONDS_PER_HOUR
            )
        );
        assert_eq!(
            DAY_ALIGNED_TIMESTAMP + 2 * SECONDS_PER_DAY,
            GroupSendCredentialResponse::default_expiration(
                DAY_ALIGNED_TIMESTAMP + 22 * SECONDS_PER_HOUR + 1
            )
        );
        assert_eq!(
            DAY_ALIGNED_TIMESTAMP + 2 * SECONDS_PER_DAY,
            GroupSendCredentialResponse::default_expiration(
                DAY_ALIGNED_TIMESTAMP + 23 * SECONDS_PER_HOUR
            )
        );
        assert_eq!(
            DAY_ALIGNED_TIMESTAMP + 2 * SECONDS_PER_DAY,
            GroupSendCredentialResponse::default_expiration(
                DAY_ALIGNED_TIMESTAMP + SECONDS_PER_DAY - 1
            )
        );
    }
}
