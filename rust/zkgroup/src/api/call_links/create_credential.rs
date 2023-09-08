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
use poksho::ShoApi;
use serde::{Deserialize, Serialize};

use crate::common::sho::Sho;
use crate::common::simple_types::*;
use crate::crypto::uid_encryption;
use crate::crypto::uid_struct::UidStruct;
use crate::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use crate::groups::UuidCiphertext;
use crate::{ZkGroupVerificationFailure, SECONDS_PER_DAY};

use super::{CallLinkPublicParams, CallLinkSecretParams};

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

#[derive(Serialize, Deserialize)]
pub struct CreateCallLinkCredentialRequestContext {
    reserved: ReservedBytes,
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
            reserved: [0],
            blinded_room_id,
            key_pair,
        }
    }

    pub fn get_request(&self) -> CreateCallLinkCredentialRequest {
        CreateCallLinkCredentialRequest {
            reserved: [0],
            blinded_room_id: self.blinded_room_id,
            public_key: *self.key_pair.public_key(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateCallLinkCredentialRequest {
    reserved: ReservedBytes,
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
        user_id: libsignal_protocol::Aci,
        timestamp: Timestamp,
        params: &GenericServerSecretParams,
        randomness: RandomnessBytes,
    ) -> CreateCallLinkCredentialResponse {
        CreateCallLinkCredentialResponse {
            reserved: [0],
            timestamp,
            blinded_credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&timestamp)
                .add_attribute(&UidStruct::from_service_id(user_id.into()))
                .add_blinded_revealed_attribute(&self.blinded_room_id)
                .issue(&params.credential_key, &self.public_key, randomness),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateCallLinkCredentialResponse {
    reserved: ReservedBytes,
    // Does not include the room ID or the user ID, because the client already knows those.
    timestamp: Timestamp,
    blinded_credential: zkcredential::issuance::blind::BlindedIssuanceProof,
}

impl CreateCallLinkCredentialRequestContext {
    pub fn receive(
        self,
        response: CreateCallLinkCredentialResponse,
        user_id: libsignal_protocol::Aci,
        params: &GenericServerPublicParams,
    ) -> Result<CreateCallLinkCredential, ZkGroupVerificationFailure> {
        if response.timestamp % SECONDS_PER_DAY != 0 {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(CreateCallLinkCredential {
            reserved: [0],
            timestamp: response.timestamp,
            credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&response.timestamp)
                .add_attribute(&UidStruct::from_service_id(user_id.into()))
                .add_blinded_revealed_attribute(&self.blinded_room_id)
                .verify(
                    &params.credential_key,
                    &self.key_pair,
                    response.blinded_credential,
                )
                .map_err(|_| ZkGroupVerificationFailure)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateCallLinkCredential {
    reserved: ReservedBytes,
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
        user_id: libsignal_protocol::Aci,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
        randomness: RandomnessBytes,
    ) -> CreateCallLinkCredentialPresentation {
        let user_id = UidStruct::from_service_id(user_id.into());
        let encrypted_user_id = call_link_params.uid_enc_key_pair.encrypt(user_id);
        CreateCallLinkCredentialPresentation {
            reserved: [0],
            timestamp: self.timestamp,
            user_id: encrypted_user_id,
            proof: zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
                .add_attribute(&user_id, &call_link_params.uid_enc_key_pair)
                .add_revealed_attribute(&CallLinkRoomIdPoint::new(room_id))
                .present(&server_params.credential_key, &self.credential, randomness),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateCallLinkCredentialPresentation {
    reserved: ReservedBytes,
    // The room ID is provided externally as part of the request.
    user_id: uid_encryption::Ciphertext,
    timestamp: Timestamp,
    proof: zkcredential::presentation::PresentationProof,
}

impl CreateCallLinkCredentialPresentation {
    pub fn verify(
        &self,
        room_id: &[u8],
        current_time_in_seconds: Timestamp,
        server_params: &GenericServerSecretParams,
        call_link_params: &CallLinkPublicParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let expiration = self
            .timestamp
            .checked_add(30 * 60 * 60) // 30 hours, to account for clock skew
            .ok_or(ZkGroupVerificationFailure)?;

        if !(self.timestamp..expiration).contains(&current_time_in_seconds) {
            return Err(ZkGroupVerificationFailure);
        }

        zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
            .add_public_attribute(&self.timestamp)
            .add_attribute(&self.user_id, &call_link_params.uid_enc_public_key)
            .add_revealed_attribute(&CallLinkRoomIdPoint::new(room_id))
            .verify(&server_params.credential_key, &self.proof)
            .map_err(|_| ZkGroupVerificationFailure)
    }

    pub fn get_user_id(&self) -> UuidCiphertext {
        UuidCiphertext {
            reserved: [0],
            ciphertext: self.user_id,
        }
    }
}
