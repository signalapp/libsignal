//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides CallLinkAuthCredential and related types.
//!
//! CreateCallLinkCredential is a MAC over:
//! - the user's ACI (provided by the chat server at issuance, passed encrypted to the calling server for verification)
//! - a "redemption time", truncated to day granularity (chosen by the chat server at issuance based on parameters from the client, passed publicly to the calling server for verification)

use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::crypto::uid_encryption;
use crate::crypto::uid_struct::UidStruct;
use crate::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use crate::groups::UuidCiphertext;
use crate::{ZkGroupVerificationFailure, SECONDS_PER_DAY};

use super::{CallLinkPublicParams, CallLinkSecretParams};

const CREDENTIAL_LABEL: &[u8] = b"20230421_Signal_CallLinkAuthCredential";

#[derive(Serialize, Deserialize)]
pub struct CallLinkAuthCredentialResponse {
    reserved: ReservedBytes,
    proof: zkcredential::issuance::IssuanceProof,
    // Does not include the user ID because the client already knows that.
    // Does not include the redemption time because that is passed externally.
}

impl CallLinkAuthCredentialResponse {
    pub fn issue_credential(
        user_id: libsignal_protocol::Aci,
        redemption_time: Timestamp,
        params: &GenericServerSecretParams,
        randomness: RandomnessBytes,
    ) -> CallLinkAuthCredentialResponse {
        let proof = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&UidStruct::from_service_id(user_id.into()))
            .add_public_attribute(&redemption_time)
            .issue(&params.credential_key, randomness);
        Self {
            reserved: [0],
            proof,
        }
    }

    pub fn receive(
        self,
        user_id: libsignal_protocol::Aci,
        redemption_time: Timestamp,
        params: &GenericServerPublicParams,
    ) -> Result<CallLinkAuthCredential, ZkGroupVerificationFailure> {
        if redemption_time % SECONDS_PER_DAY != 0 {
            return Err(ZkGroupVerificationFailure);
        }

        let raw_credential = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&UidStruct::from_service_id(user_id.into()))
            .add_public_attribute(&redemption_time)
            .verify(&params.credential_key, self.proof)
            .map_err(|_| ZkGroupVerificationFailure)?;
        Ok(CallLinkAuthCredential {
            reserved: [0],
            credential: raw_credential,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct CallLinkAuthCredential {
    reserved: ReservedBytes,
    credential: zkcredential::credentials::Credential,
    // Does not include the user ID because the client already knows that.
    // Does not include the redemption time because that's used as a key to lookup up this credential.
}

impl CallLinkAuthCredential {
    pub fn present(
        &self,
        user_id: libsignal_protocol::Aci,
        redemption_time: Timestamp,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
        randomness: RandomnessBytes,
    ) -> CallLinkAuthCredentialPresentation {
        let uid_attr = UidStruct::from_service_id(user_id.into());
        let proof = zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&uid_attr, &call_link_params.uid_enc_key_pair)
            .present(&server_params.credential_key, &self.credential, randomness);
        CallLinkAuthCredentialPresentation {
            reserved: [0],
            proof,
            ciphertext: call_link_params.uid_enc_key_pair.encrypt(uid_attr),
            redemption_time,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CallLinkAuthCredentialPresentation {
    pub(crate) reserved: ReservedBytes,
    pub(crate) proof: zkcredential::presentation::PresentationProof,
    pub(crate) ciphertext: uid_encryption::Ciphertext,
    pub(crate) redemption_time: Timestamp,
}

impl CallLinkAuthCredentialPresentation {
    pub fn verify(
        &self,
        current_time_in_seconds: Timestamp,
        server_params: &GenericServerSecretParams,
        call_link_params: &CallLinkPublicParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        crate::ServerSecretParams::check_auth_credential_redemption_time(
            self.redemption_time,
            current_time_in_seconds,
        )?;

        zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
            .add_attribute(&self.ciphertext, &call_link_params.uid_enc_public_key)
            .add_public_attribute(&self.redemption_time)
            .verify(&server_params.credential_key, &self.proof)
            .map_err(|_| ZkGroupVerificationFailure)
    }

    pub fn get_user_id(&self) -> UuidCiphertext {
        UuidCiphertext {
            reserved: [0],
            ciphertext: self.ciphertext,
        }
    }
}
