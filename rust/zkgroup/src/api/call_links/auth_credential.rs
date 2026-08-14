//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides CallLinkAuthCredential and related types.
//!
//! CreateCallLinkCredential is a MAC over:
//! - the user's ACI (provided by the chat server at issuance, passed encrypted to the calling server for verification)
//! - a "redemption time", truncated to day granularity (chosen by the chat server at issuance based on parameters from the client, passed publicly to the calling server for verification)

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use super::{CallLinkPublicParams, CallLinkSecretParams};
use crate::ZkGroupVerificationFailure;
use crate::common::simple_types::*;
use crate::crypto::uid_encryption;
use crate::crypto::uid_struct::UidStruct;
use crate::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use crate::groups::UuidCiphertext;

const CREDENTIAL_LABEL: &[u8] = b"20230421_Signal_CallLinkAuthCredential";

/// Since the structure of each version is the same, we use a dynamic version field instead of the
/// ADT-based approach of e.g. `AnyProfileKeyCredentialPresentation`. If we ever need a new version
/// that changes the representation, we should switch to that model.
#[derive(Clone, Copy, Debug, PartialDefault, Serialize, Deserialize, derive_more::TryFrom)]
#[repr(u8)]
#[try_from(repr)]
#[serde(try_from = "u8", into = "u8")]
enum AuthCredentialVersion {
    #[partial_default]
    WithLegacyParams = 0,
    WithStandardParams = 1,
}

impl From<AuthCredentialVersion> for u8 {
    fn from(value: AuthCredentialVersion) -> Self {
        value as u8
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CallLinkAuthCredentialResponse {
    version: AuthCredentialVersion,
    proof: zkcredential::issuance::IssuanceProof,
    // Does not include the user ID because the client already knows that.
    // Does not include the redemption time because that is passed externally.
}

impl CallLinkAuthCredentialResponse {
    pub fn issue_credential(
        user_id: libsignal_core::Aci,
        redemption_time: Timestamp,
        params: &GenericServerSecretParams,
        randomness: RandomnessBytes,
    ) -> CallLinkAuthCredentialResponse {
        let builder = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&UidStruct::from_service_id(user_id.into()))
            .add_public_attribute(&redemption_time);

        match params {
            GenericServerSecretParams::V0(params) => Self {
                version: AuthCredentialVersion::WithLegacyParams,
                proof: builder.issue(&params.credential_key, randomness),
            },
            GenericServerSecretParams::V1(params) => Self {
                version: AuthCredentialVersion::WithStandardParams,
                proof: builder.issue(&params.credential_key, randomness),
            },
        }
    }

    pub fn receive(
        self,
        user_id: libsignal_core::Aci,
        redemption_time: Timestamp,
        params: &GenericServerPublicParams,
    ) -> Result<CallLinkAuthCredential, ZkGroupVerificationFailure> {
        let credential_key = match (self.version, params) {
            (AuthCredentialVersion::WithLegacyParams, GenericServerPublicParams::V0(params)) => {
                &params.credential_key
            }
            (AuthCredentialVersion::WithStandardParams, GenericServerPublicParams::V1(params)) => {
                &params.credential_key
            }
            (_, _) => {
                return Err(ZkGroupVerificationFailure);
            }
        };

        if !redemption_time.is_day_aligned() {
            return Err(ZkGroupVerificationFailure);
        }

        let raw_credential = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&UidStruct::from_service_id(user_id.into()))
            .add_public_attribute(&redemption_time)
            .verify(credential_key, self.proof)
            .map_err(|_| ZkGroupVerificationFailure)?;
        Ok(CallLinkAuthCredential {
            version: self.version,
            credential: raw_credential,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CallLinkAuthCredential {
    version: AuthCredentialVersion,
    credential: zkcredential::credentials::Credential,
    // Does not include the user ID because the client already knows that.
    // Does not include the redemption time because that's used as a key to lookup up this credential.
}

impl CallLinkAuthCredential {
    pub fn present(
        &self,
        user_id: libsignal_core::Aci,
        redemption_time: Timestamp,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
        randomness: RandomnessBytes,
    ) -> CallLinkAuthCredentialPresentation {
        let present_proof: &dyn Fn(zkcredential::presentation::PresentationProofBuilder) -> _ =
            match (self.version, server_params) {
                (
                    AuthCredentialVersion::WithLegacyParams,
                    GenericServerPublicParams::V0(params),
                ) => &|builder| {
                    builder.present::<zkcredential::credentials::LegacyMode>(
                        &params.credential_key,
                        &self.credential,
                        randomness,
                    )
                },
                (
                    AuthCredentialVersion::WithStandardParams,
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

        let uid_attr = UidStruct::from_service_id(user_id.into());
        let proof = present_proof(
            zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
                .add_attribute(&uid_attr, &call_link_params.uid_enc_key_pair),
        );
        CallLinkAuthCredentialPresentation {
            version: self.version,
            proof,
            ciphertext: call_link_params.uid_enc_key_pair.encrypt(&uid_attr),
            redemption_time,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct CallLinkAuthCredentialPresentation {
    version: AuthCredentialVersion,
    pub(crate) proof: zkcredential::presentation::PresentationProof,
    pub(crate) ciphertext: uid_encryption::Ciphertext,
    pub(crate) redemption_time: Timestamp,
}

impl CallLinkAuthCredentialPresentation {
    pub fn verify(
        &self,
        current_time: Timestamp,
        server_params: &GenericServerSecretParams,
        call_link_params: &CallLinkPublicParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let verify_proof: &dyn Fn(zkcredential::presentation::PresentationProofVerifier) -> _ =
            match (self.version, server_params) {
                (
                    AuthCredentialVersion::WithLegacyParams,
                    GenericServerSecretParams::V0(params),
                ) => &|builder| builder.verify(&params.credential_key, &self.proof),
                (
                    AuthCredentialVersion::WithStandardParams,
                    GenericServerSecretParams::V1(params),
                ) => &|builder| builder.verify(&params.credential_key, &self.proof),
                (_, _) => {
                    return Err(ZkGroupVerificationFailure);
                }
            };

        crate::ServerSecretParams::check_auth_credential_redemption_time(
            self.redemption_time,
            current_time,
        )?;

        verify_proof(
            zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
                .add_attribute(&self.ciphertext, &call_link_params.uid_enc_public_key)
                .add_public_attribute(&self.redemption_time),
        )
        .map_err(|_| ZkGroupVerificationFailure)
    }

    /// A temporary helper for matching legacy credentials with legacy params and standard
    /// credentials with standard params.
    ///
    /// This method will be removed when all uses of the legacy params are gone.
    pub fn verify_against_appropriate_params(
        &self,
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
            AuthCredentialVersion::WithLegacyParams => old_server_params,
            AuthCredentialVersion::WithStandardParams => new_server_params,
        };
        self.verify(current_time, server_params, call_link_params)
    }

    pub fn get_user_id(&self) -> UuidCiphertext {
        UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.ciphertext,
        }
    }
}
