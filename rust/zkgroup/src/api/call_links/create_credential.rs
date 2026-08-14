//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides CreateCallLinkCredential and related types.
//!
//! CreateCallLinkCredential is a MAC over:
//! - a call link room ID (chosen by the client, blinded at issuance, revealed for verification)
//! - the user's ACI (provided by the chat server at issuance, passed encrypted to the calling server for verification)
//! - a timestamp, truncated to day granularity (chosen by the chat server at issuance, passed publicly to the calling server for verification)

use curve25519_dalek::ristretto::RistrettoPoint;
use partial_default::PartialDefault;
use poksho::ShoApi;
use serde::{Deserialize, Serialize};

use super::{CallLinkPublicParams, CallLinkSecretParams};
use crate::ZkGroupVerificationFailure;
use crate::common::serialization::ReservedByte;
use crate::common::sho::Sho;
use crate::common::simple_types::*;
use crate::crypto::uid_encryption;
use crate::crypto::uid_struct::UidStruct;
use crate::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use crate::groups::UuidCiphertext;

#[derive(Serialize, Deserialize, Clone, Copy)]
struct CallLinkRoomIdPoint(RistrettoPoint);

impl CallLinkRoomIdPoint {
    fn new(room_id: &[u8]) -> Self {
        Self(Sho::new(b"20230413_Signal_CallLinkRoomId", room_id).get_point())
    }
}

impl zkcredential::attributes::RevealedAttribute for CallLinkRoomIdPoint {
    fn as_point(&self) -> RistrettoPoint {
        self.0
    }
}

const CREDENTIAL_LABEL: &[u8] = b"20230413_Signal_CreateCallLinkCredential";

/// Since the structure of each version is the same, we use a dynamic version field instead of the
/// ADT-based approach of e.g. `AnyProfileKeyCredentialPresentation`. If we ever need a new version
/// that changes the representation, we should switch to that model.
#[derive(Clone, Copy, Debug, PartialDefault, Serialize, Deserialize, derive_more::TryFrom)]
#[repr(u8)]
#[try_from(repr)]
#[serde(try_from = "u8", into = "u8")]
enum CreateCredentialVersion {
    #[partial_default]
    WithLegacyParams = 0,
    WithStandardParams = 1,
}

impl From<CreateCredentialVersion> for u8 {
    fn from(value: CreateCredentialVersion) -> Self {
        value as u8
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CreateCallLinkCredentialRequestContext {
    reserved: ReservedByte,
    blinded_room_id: zkcredential::issuance::blind::BlindedPoint,
    key_pair: zkcredential::issuance::blind::BlindingKeyPair,
}

impl CreateCallLinkCredentialRequestContext {
    pub fn new(room_id: &[u8], randomness: RandomnessBytes) -> Self {
        let mut sho =
            poksho::ShoHmacSha256::new(b"20230413_Signal_CreateCallLinkCredentialRequest");
        sho.absorb_and_ratchet(&randomness);

        let key_pair = zkcredential::issuance::blind::BlindingKeyPair::generate(&mut sho);
        let blinded_room_id = key_pair
            .blind(&CallLinkRoomIdPoint::new(room_id), &mut sho)
            .into();

        Self {
            reserved: Default::default(),
            blinded_room_id,
            key_pair,
        }
    }

    pub fn get_request(&self) -> CreateCallLinkCredentialRequest {
        CreateCallLinkCredentialRequest {
            reserved: Default::default(),
            blinded_room_id: self.blinded_room_id,
            public_key: *self.key_pair.public_key(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CreateCallLinkCredentialRequest {
    reserved: ReservedByte,
    blinded_room_id: zkcredential::issuance::blind::BlindedPoint,
    public_key: zkcredential::issuance::blind::BlindingPublicKey,
    // Note that unlike ProfileKeyCredentialRequest, we don't have a proof. This is because our only
    // "blinded" attribute is derived from the room ID, making it effectively random as far as the
    // issuing server is concerned. Whether or not the server is willing to issue a
    // CreateCallLinkCredential doesn't depend on what that room ID is; in the very unlikely case of
    // a collision, the client will get a failure when they use the credential presentation to
    // actually attempt to create the link.
    //
    // (RingRTC will only generate room IDs of a certain form, but we don't need to enforce that
    // using zkproofs; we can do so more directly in RingRTC and on the calling server.)
}

impl CreateCallLinkCredentialRequest {
    pub fn issue(
        &self,
        user_id: libsignal_core::Aci,
        timestamp: Timestamp,
        params: &GenericServerSecretParams,
        randomness: RandomnessBytes,
    ) -> CreateCallLinkCredentialResponse {
        let builder = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_public_attribute(&timestamp)
            .add_attribute(&UidStruct::from_service_id(user_id.into()))
            .add_blinded_revealed_attribute(&self.blinded_room_id);

        match params {
            GenericServerSecretParams::V0(params) => CreateCallLinkCredentialResponse {
                version: CreateCredentialVersion::WithLegacyParams,
                timestamp,
                blinded_credential: builder.issue(
                    &params.credential_key,
                    &self.public_key,
                    randomness,
                ),
            },
            GenericServerSecretParams::V1(params) => CreateCallLinkCredentialResponse {
                version: CreateCredentialVersion::WithStandardParams,
                timestamp,
                blinded_credential: builder.issue(
                    &params.credential_key,
                    &self.public_key,
                    randomness,
                ),
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CreateCallLinkCredentialResponse {
    version: CreateCredentialVersion,
    // Does not include the room ID or the user ID, because the client already knows those.
    timestamp: Timestamp,
    blinded_credential: zkcredential::issuance::blind::BlindedIssuanceProof,
}

impl CreateCallLinkCredentialRequestContext {
    pub fn receive(
        self,
        response: CreateCallLinkCredentialResponse,
        user_id: libsignal_core::Aci,
        params: &GenericServerPublicParams,
    ) -> Result<CreateCallLinkCredential, ZkGroupVerificationFailure> {
        let credential_key = match (response.version, params) {
            (CreateCredentialVersion::WithLegacyParams, GenericServerPublicParams::V0(params)) => {
                &params.credential_key
            }
            (
                CreateCredentialVersion::WithStandardParams,
                GenericServerPublicParams::V1(params),
            ) => &params.credential_key,
            (_, _) => {
                return Err(ZkGroupVerificationFailure);
            }
        };

        if !response.timestamp.is_day_aligned() {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(CreateCallLinkCredential {
            version: response.version,
            timestamp: response.timestamp,
            credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&response.timestamp)
                .add_attribute(&UidStruct::from_service_id(user_id.into()))
                .add_blinded_revealed_attribute(&self.blinded_room_id)
                .verify(credential_key, &self.key_pair, response.blinded_credential)
                .map_err(|_| ZkGroupVerificationFailure)?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CreateCallLinkCredential {
    version: CreateCredentialVersion,
    // We could avoid having to pass in the room ID or user ID again if we saved them here, but
    // that's readily available information in the apps, so we may as well keep the credential
    // small.
    timestamp: Timestamp,
    credential: zkcredential::credentials::Credential,
}

impl CreateCallLinkCredential {
    pub fn present(
        &self,
        room_id: &[u8],
        user_id: libsignal_core::Aci,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
        randomness: RandomnessBytes,
    ) -> CreateCallLinkCredentialPresentation {
        let present_proof: &dyn Fn(zkcredential::presentation::PresentationProofBuilder) -> _ =
            match (self.version, server_params) {
                (
                    CreateCredentialVersion::WithLegacyParams,
                    GenericServerPublicParams::V0(params),
                ) => &|builder| {
                    builder.present::<zkcredential::credentials::LegacyMode>(
                        &params.credential_key,
                        &self.credential,
                        randomness,
                    )
                },
                (
                    CreateCredentialVersion::WithStandardParams,
                    GenericServerPublicParams::V1(params),
                ) => &|builder| {
                    builder.present::<zkcredential::credentials::StandardMode>(
                        &params.credential_key,
                        &self.credential,
                        randomness,
                    )
                },
                (_, _) => {
                    panic!("these params are not the ones used to receive the credential");
                }
            };

        let user_id = UidStruct::from_service_id(user_id.into());
        let encrypted_user_id = call_link_params.uid_enc_key_pair.encrypt(&user_id);
        let builder = zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&user_id, &call_link_params.uid_enc_key_pair)
            .add_revealed_attribute(&CallLinkRoomIdPoint::new(room_id));

        CreateCallLinkCredentialPresentation {
            version: self.version,
            timestamp: self.timestamp,
            user_id: encrypted_user_id,
            proof: present_proof(builder),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CreateCallLinkCredentialPresentation {
    version: CreateCredentialVersion,
    // The room ID is provided externally as part of the request.
    user_id: zkcredential::attributes::Ciphertext<uid_encryption::UidEncryptionDomain>,
    timestamp: Timestamp,
    proof: zkcredential::presentation::PresentationProof,
}

impl CreateCallLinkCredentialPresentation {
    pub fn verify(
        &self,
        room_id: &[u8],
        current_time: Timestamp,
        server_params: &GenericServerSecretParams,
        call_link_params: &CallLinkPublicParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let expiration = self
            .timestamp
            .checked_add_seconds(30 * 60 * 60) // 30 hours, to account for clock skew
            .ok_or(ZkGroupVerificationFailure)?;

        if !(self.timestamp..expiration).contains(&current_time) {
            return Err(ZkGroupVerificationFailure);
        }

        let verify_proof: &dyn Fn(zkcredential::presentation::PresentationProofVerifier) -> _ =
            match (self.version, server_params) {
                (
                    CreateCredentialVersion::WithLegacyParams,
                    GenericServerSecretParams::V0(params),
                ) => &|builder| builder.verify(&params.credential_key, &self.proof),
                (
                    CreateCredentialVersion::WithStandardParams,
                    GenericServerSecretParams::V1(params),
                ) => &|builder| builder.verify(&params.credential_key, &self.proof),
                (_, _) => {
                    return Err(ZkGroupVerificationFailure);
                }
            };

        verify_proof(
            zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
                .add_public_attribute(&self.timestamp)
                .add_attribute(&self.user_id, &call_link_params.uid_enc_public_key)
                .add_revealed_attribute(&CallLinkRoomIdPoint::new(room_id)),
        )
        .map_err(|_| ZkGroupVerificationFailure)
    }

    /// A temporary helper for matching legacy credentials with legacy params and standard
    /// credentials with standard params.
    ///
    /// This method will be removed when all uses of the legacy params are gone.
    pub fn verify_against_appropriate_params(
        &self,
        room_id: &[u8],
        current_time: Timestamp,
        old_server_params: &GenericServerSecretParams,
        new_server_params: &GenericServerSecretParams,
        call_link_params: &CallLinkPublicParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        // We could enforce these checks in the type system, but that makes it harder for callers
        // that are otherwise not thinking about the two kinds of params.
        assert!(
            matches!(old_server_params, GenericServerSecretParams::V0(_)),
            "old params should always use legacy keys (did you reverse the arguments to verify_against_appropriate_params?)"
        );
        assert!(
            matches!(new_server_params, GenericServerSecretParams::V1(_)),
            "new params should always use standard keys (did you pass the same params to both arguments?)"
        );
        let server_params = match self.version {
            CreateCredentialVersion::WithLegacyParams => old_server_params,
            CreateCredentialVersion::WithStandardParams => new_server_params,
        };
        self.verify(room_id, current_time, server_params, call_link_params)
    }

    pub fn get_user_id(&self) -> UuidCiphertext {
        UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.user_id,
        }
    }
}
