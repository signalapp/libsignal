//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerSecretParams {
    pub(crate) reserved: ReservedBytes,
    pub(crate) auth_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::AuthCredential>,

    // Now unused
    pub(crate) profile_key_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::ProfileKeyCredential>,

    sig_key_pair: crypto::signature::KeyPair,
    receipt_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::ReceiptCredential>,

    // Now unused
    pni_credentials_key_pair: crypto::credentials::KeyPair<crypto::credentials::PniCredential>,

    expiring_profile_key_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::ExpiringProfileKeyCredential>,
    auth_credentials_with_pni_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::AuthCredentialWithPni>,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerPublicParams {
    pub(crate) reserved: ReservedBytes,
    pub(crate) auth_credentials_public_key: crypto::credentials::PublicKey,

    // Now unused
    pub(crate) profile_key_credentials_public_key: crypto::credentials::PublicKey,

    sig_public_key: crypto::signature::PublicKey,
    receipt_credentials_public_key: crypto::credentials::PublicKey,

    // Now unused
    pni_credentials_public_key: crypto::credentials::PublicKey,

    expiring_profile_key_credentials_public_key: crypto::credentials::PublicKey,
    auth_credentials_with_pni_public_key: crypto::credentials::PublicKey,
}

impl ServerSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_Generate",
            &randomness,
        );

        let auth_credentials_key_pair = crypto::credentials::KeyPair::generate(&mut sho);
        let profile_key_credentials_key_pair = crypto::credentials::KeyPair::generate(&mut sho);
        let sig_key_pair = crypto::signature::KeyPair::generate(&mut sho);
        let receipt_credentials_key_pair = crypto::credentials::KeyPair::generate(&mut sho);
        let pni_credentials_key_pair = crypto::credentials::KeyPair::generate(&mut sho);
        let expiring_profile_key_credentials_key_pair =
            crypto::credentials::KeyPair::generate(&mut sho);
        let auth_credentials_with_pni_key_pair = crypto::credentials::KeyPair::generate(&mut sho);

        Self {
            reserved: Default::default(),
            auth_credentials_key_pair,
            profile_key_credentials_key_pair,
            sig_key_pair,
            receipt_credentials_key_pair,
            pni_credentials_key_pair,
            expiring_profile_key_credentials_key_pair,
            auth_credentials_with_pni_key_pair,
        }
    }

    pub fn get_public_params(&self) -> ServerPublicParams {
        ServerPublicParams {
            reserved: Default::default(),
            auth_credentials_public_key: self.auth_credentials_key_pair.get_public_key(),
            profile_key_credentials_public_key: self
                .profile_key_credentials_key_pair
                .get_public_key(),
            sig_public_key: self.sig_key_pair.get_public_key(),
            receipt_credentials_public_key: self.receipt_credentials_key_pair.get_public_key(),
            pni_credentials_public_key: self.pni_credentials_key_pair.get_public_key(),
            expiring_profile_key_credentials_public_key: self
                .expiring_profile_key_credentials_key_pair
                .get_public_key(),
            auth_credentials_with_pni_public_key: self
                .auth_credentials_with_pni_key_pair
                .get_public_key(),
        }
    }

    pub fn sign(&self, randomness: RandomnessBytes, message: &[u8]) -> NotarySignatureBytes {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_Sign",
            &randomness,
        );
        self.sig_key_pair.sign(message, &mut sho)
    }

    pub fn issue_auth_credential(
        &self,
        randomness: RandomnessBytes,
        aci: libsignal_protocol::Aci,
        redemption_time: CoarseRedemptionTime,
    ) -> api::auth::AuthCredentialResponse {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_IssueAuthCredential",
            &randomness,
        );

        let uid = crypto::uid_struct::UidStruct::from_service_id(aci.into());
        let credential =
            self.auth_credentials_key_pair
                .create_auth_credential(uid, redemption_time, &mut sho);
        let proof = crypto::proofs::AuthCredentialIssuanceProof::new(
            self.auth_credentials_key_pair,
            credential,
            uid,
            redemption_time,
            &mut sho,
        );
        api::auth::AuthCredentialResponse {
            reserved: Default::default(),
            credential,
            proof,
        }
    }

    fn issue_auth_credential_with_pni(
        &self,
        randomness: RandomnessBytes,
        aci: libsignal_protocol::Aci,
        pni: libsignal_protocol::Pni,
        redemption_time: Timestamp,
        encode_pni_as_aci_for_backward_compatibility: bool,
    ) -> api::auth::AuthCredentialWithPniResponse {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220617_Random_ServerSecretParams_IssueAuthCredentialWithPni",
            &randomness,
        );

        let aci_struct = crypto::uid_struct::UidStruct::from_service_id(aci.into());
        let pni_struct = if encode_pni_as_aci_for_backward_compatibility {
            let pni_as_aci = libsignal_protocol::Aci::from(uuid::Uuid::from(pni));
            crypto::uid_struct::UidStruct::from_service_id(pni_as_aci.into())
        } else {
            crypto::uid_struct::UidStruct::from_service_id(pni.into())
        };
        let credential = self
            .auth_credentials_with_pni_key_pair
            .create_auth_credential_with_pni(aci_struct, pni_struct, redemption_time, &mut sho);
        let proof = crypto::proofs::AuthCredentialWithPniIssuanceProof::new(
            self.auth_credentials_with_pni_key_pair,
            credential,
            aci_struct,
            pni_struct,
            redemption_time,
            &mut sho,
        );
        api::auth::AuthCredentialWithPniResponse {
            reserved: Default::default(),
            credential,
            proof,
        }
    }

    pub fn issue_auth_credential_with_pni_as_service_id(
        &self,
        randomness: RandomnessBytes,
        aci: libsignal_protocol::Aci,
        pni: libsignal_protocol::Pni,
        redemption_time: Timestamp,
    ) -> api::auth::AuthCredentialWithPniResponse {
        self.issue_auth_credential_with_pni(randomness, aci, pni, redemption_time, false)
    }

    pub fn issue_auth_credential_with_pni_as_aci(
        &self,
        randomness: RandomnessBytes,
        aci: libsignal_protocol::Aci,
        pni: libsignal_protocol::Pni,
        redemption_time: Timestamp,
    ) -> api::auth::AuthCredentialWithPniResponse {
        self.issue_auth_credential_with_pni(randomness, aci, pni, redemption_time, true)
    }

    /// Checks that `current_time_in_seconds` is within the validity window defined by
    /// `redemption_time_in_seconds`.
    ///
    /// All times are relative to SystemTime::UNIX_EPOCH,
    /// but we don't actually use SystemTime because it's too small on 32-bit Linux.
    pub(crate) fn check_auth_credential_redemption_time(
        redemption_time_in_seconds: Timestamp,
        current_time_in_seconds: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let acceptable_start_time = redemption_time_in_seconds - SECONDS_PER_DAY;
        let acceptable_end_time = redemption_time_in_seconds + 2 * SECONDS_PER_DAY;

        if !(acceptable_start_time..=acceptable_end_time).contains(&current_time_in_seconds) {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(())
    }

    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AnyAuthCredentialPresentation,
        current_time_in_seconds: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        Self::check_auth_credential_redemption_time(
            presentation.get_redemption_time(),
            current_time_in_seconds,
        )?;

        match presentation {
            api::auth::AnyAuthCredentialPresentation::V2(presentation) => {
                presentation.proof.verify(
                    self.auth_credentials_key_pair,
                    group_public_params.uid_enc_public_key,
                    presentation.ciphertext,
                    presentation.redemption_time,
                )
            }

            api::auth::AnyAuthCredentialPresentation::V3(presentation) => {
                presentation.proof.verify(
                    self.auth_credentials_with_pni_key_pair,
                    group_public_params.uid_enc_public_key,
                    presentation.aci_ciphertext,
                    presentation.pni_ciphertext,
                    presentation.redemption_time,
                )
            }
        }
    }

    pub fn verify_auth_credential_presentation_v2(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AuthCredentialPresentationV2,
        current_time_in_days: CoarseRedemptionTime,
    ) -> Result<(), ZkGroupVerificationFailure> {
        Self::check_auth_credential_redemption_time(
            u64::from(presentation.get_redemption_time()) * SECONDS_PER_DAY,
            u64::from(current_time_in_days) * SECONDS_PER_DAY,
        )?;
        presentation.proof.verify(
            self.auth_credentials_key_pair,
            group_public_params.uid_enc_public_key,
            presentation.ciphertext,
            presentation.redemption_time,
        )
    }

    pub fn verify_auth_credential_with_pni_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AuthCredentialWithPniPresentation,
        current_time_in_seconds: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        Self::check_auth_credential_redemption_time(
            presentation.get_redemption_time(),
            current_time_in_seconds,
        )?;
        presentation.proof.verify(
            self.auth_credentials_with_pni_key_pair,
            group_public_params.uid_enc_public_key,
            presentation.aci_ciphertext,
            presentation.pni_ciphertext,
            presentation.redemption_time,
        )
    }

    pub fn verify_profile_key_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::profiles::AnyProfileKeyCredentialPresentation,
        current_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        match presentation {
            api::profiles::AnyProfileKeyCredentialPresentation::V1(_) => {
                Err(ZkGroupVerificationFailure)
            }

            api::profiles::AnyProfileKeyCredentialPresentation::V2(_) => {
                Err(ZkGroupVerificationFailure)
            }

            api::profiles::AnyProfileKeyCredentialPresentation::V3(presentation) => self
                .verify_expiring_profile_key_credential_presentation(
                    group_public_params,
                    presentation,
                    current_time,
                ),
        }
    }

    pub fn verify_expiring_profile_key_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::profiles::ExpiringProfileKeyCredentialPresentation,
        current_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let credentials_key_pair = self.expiring_profile_key_credentials_key_pair;
        let uid_enc_public_key = group_public_params.uid_enc_public_key;
        let profile_key_enc_public_key = group_public_params.profile_key_enc_public_key;

        presentation.proof.verify(
            credentials_key_pair,
            presentation.uid_enc_ciphertext,
            uid_enc_public_key,
            presentation.profile_key_enc_ciphertext,
            profile_key_enc_public_key,
            presentation.credential_expiration_time,
        )?;

        if presentation.credential_expiration_time <= current_time {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(())
    }

    pub fn issue_expiring_profile_key_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::profiles::ProfileKeyCredentialRequest,
        aci: libsignal_protocol::Aci,
        commitment: api::profiles::ProfileKeyCommitment,
        credential_expiration_time: Timestamp,
    ) -> Result<api::profiles::ExpiringProfileKeyCredentialResponse, ZkGroupVerificationFailure>
    {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220508_Random_ServerSecretParams_IssueExpiringProfileKeyCredential",
            &randomness,
        );

        request.proof.verify(
            request.public_key,
            request.ciphertext,
            commitment.commitment,
        )?;

        let uid = crypto::uid_struct::UidStruct::from_service_id(aci.into());
        let blinded_credential_with_secret_nonce = self
            .expiring_profile_key_credentials_key_pair
            .create_blinded_expiring_profile_key_credential(
                uid,
                request.public_key,
                request.ciphertext,
                credential_expiration_time,
                &mut sho,
            );

        let proof = crypto::proofs::ExpiringProfileKeyCredentialIssuanceProof::new(
            self.expiring_profile_key_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            uid,
            credential_expiration_time,
            &mut sho,
        );

        Ok(api::profiles::ExpiringProfileKeyCredentialResponse {
            version: Default::default(),
            blinded_credential: blinded_credential_with_secret_nonce
                .get_blinded_expiring_profile_key_credential(),
            credential_expiration_time,
            proof,
        })
    }

    pub fn issue_receipt_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::receipts::ReceiptCredentialRequest,
        receipt_expiration_time: Timestamp,
        receipt_level: ReceiptLevel,
    ) -> api::receipts::ReceiptCredentialResponse {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20210919_Random_ServerSecretParams_IssueReceiptCredential",
            &randomness,
        );

        let blinded_credential_with_secret_nonce = self
            .receipt_credentials_key_pair
            .create_blinded_receipt_credential(
                request.public_key,
                request.ciphertext,
                receipt_expiration_time,
                receipt_level,
                &mut sho,
            );

        let proof = crypto::proofs::ReceiptCredentialIssuanceProof::new(
            self.receipt_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            receipt_expiration_time,
            receipt_level,
            &mut sho,
        );

        api::receipts::ReceiptCredentialResponse {
            reserved: Default::default(),
            receipt_expiration_time,
            receipt_level,
            blinded_credential: blinded_credential_with_secret_nonce
                .get_blinded_receipt_credential(),
            proof,
        }
    }

    pub fn verify_receipt_credential_presentation(
        &self,
        presentation: &api::receipts::ReceiptCredentialPresentation,
    ) -> Result<(), ZkGroupVerificationFailure> {
        presentation.proof.verify(
            self.receipt_credentials_key_pair,
            presentation.get_receipt_struct(),
        )
    }
}

impl ServerPublicParams {
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: NotarySignatureBytes,
    ) -> Result<(), ZkGroupVerificationFailure> {
        self.sig_public_key.verify(message, signature)
    }

    pub fn receive_auth_credential(
        &self,
        aci: libsignal_protocol::Aci,
        redemption_time: CoarseRedemptionTime,
        response: &api::auth::AuthCredentialResponse,
    ) -> Result<api::auth::AuthCredential, ZkGroupVerificationFailure> {
        let uid = crypto::uid_struct::UidStruct::from_service_id(aci.into());
        response.proof.verify(
            self.auth_credentials_public_key,
            response.credential,
            uid,
            redemption_time,
        )?;

        Ok(api::auth::AuthCredential {
            reserved: Default::default(),
            credential: response.credential,
            uid,
            redemption_time,
        })
    }

    fn receive_auth_credential_with_pni(
        &self,
        aci: libsignal_protocol::Aci,
        pni: libsignal_protocol::Pni,
        redemption_time: Timestamp,
        response: &api::auth::AuthCredentialWithPniResponse,
        encode_pni_as_aci_for_backward_compatibility: bool,
    ) -> Result<api::auth::AuthCredentialWithPni, ZkGroupVerificationFailure> {
        let aci_struct = crypto::uid_struct::UidStruct::from_service_id(aci.into());
        let pni_struct = if encode_pni_as_aci_for_backward_compatibility {
            // Older AuthCredentialWithPnis used the same encoding for PNIs as ACIs.
            // This won't match up with UuidCiphertexts that hold correctly-encoded PNIs,
            // but can still be used as a valid ACI credential.
            let pni_as_aci = libsignal_protocol::Aci::from(uuid::Uuid::from(pni));
            crypto::uid_struct::UidStruct::from_service_id(pni_as_aci.into())
        } else {
            crypto::uid_struct::UidStruct::from_service_id(pni.into())
        };
        response.proof.verify(
            self.auth_credentials_with_pni_public_key,
            response.credential,
            aci_struct,
            pni_struct,
            redemption_time,
        )?;

        Ok(api::auth::AuthCredentialWithPni {
            reserved: Default::default(),
            credential: response.credential,
            aci: aci_struct,
            pni: pni_struct,
            redemption_time,
        })
    }

    pub fn receive_auth_credential_with_pni_as_service_id(
        &self,
        aci: libsignal_protocol::Aci,
        pni: libsignal_protocol::Pni,
        redemption_time: Timestamp,
        response: &api::auth::AuthCredentialWithPniResponse,
    ) -> Result<api::auth::AuthCredentialWithPni, ZkGroupVerificationFailure> {
        self.receive_auth_credential_with_pni(aci, pni, redemption_time, response, false)
    }

    pub fn receive_auth_credential_with_pni_as_aci(
        &self,
        aci: libsignal_protocol::Aci,
        pni: libsignal_protocol::Pni,
        redemption_time: Timestamp,
        response: &api::auth::AuthCredentialWithPniResponse,
    ) -> Result<api::auth::AuthCredentialWithPni, ZkGroupVerificationFailure> {
        self.receive_auth_credential_with_pni(aci, pni, redemption_time, response, true)
    }

    pub fn create_auth_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredential,
    ) -> api::auth::AnyAuthCredentialPresentation {
        let presentation_v2 = self.create_auth_credential_presentation_v2(
            randomness,
            group_secret_params,
            auth_credential,
        );
        api::auth::AnyAuthCredentialPresentation::V2(presentation_v2)
    }

    pub fn create_auth_credential_presentation_v2(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredential,
    ) -> api::auth::AuthCredentialPresentationV2 {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220120_Random_ServerPublicParams_CreateAuthCredentialPresentationV2",
            &randomness,
        );

        let uuid_ciphertext = group_secret_params.encrypt_uid_struct(auth_credential.uid);

        let proof = crypto::proofs::AuthCredentialPresentationProofV2::new(
            self.auth_credentials_public_key,
            group_secret_params.uid_enc_key_pair,
            auth_credential.credential,
            auth_credential.uid,
            uuid_ciphertext.ciphertext,
            auth_credential.redemption_time,
            &mut sho,
        );

        api::auth::AuthCredentialPresentationV2 {
            version: [PRESENTATION_VERSION_2],
            proof,
            ciphertext: uuid_ciphertext.ciphertext,
            redemption_time: auth_credential.redemption_time,
        }
    }

    pub fn create_auth_credential_with_pni_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredentialWithPni,
    ) -> api::auth::AuthCredentialWithPniPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220617_Random_ServerPublicParams_CreateAuthCredentialWithPniPresentation",
            &randomness,
        );

        let aci_ciphertext = group_secret_params.encrypt_uid_struct(auth_credential.aci);
        let pni_ciphertext = group_secret_params.encrypt_uid_struct(auth_credential.pni);

        let proof = crypto::proofs::AuthCredentialWithPniPresentationProof::new(
            self.auth_credentials_with_pni_public_key,
            group_secret_params.uid_enc_key_pair,
            auth_credential.credential,
            auth_credential.aci,
            aci_ciphertext.ciphertext,
            auth_credential.pni,
            pni_ciphertext.ciphertext,
            auth_credential.redemption_time,
            &mut sho,
        );

        api::auth::AuthCredentialWithPniPresentation {
            version: [PRESENTATION_VERSION_3],
            proof,
            aci_ciphertext: aci_ciphertext.ciphertext,
            pni_ciphertext: pni_ciphertext.ciphertext,
            redemption_time: auth_credential.redemption_time,
        }
    }

    pub fn create_profile_key_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        aci: libsignal_protocol::Aci,
        profile_key: api::profiles::ProfileKey,
    ) -> api::profiles::ProfileKeyCredentialRequestContext {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateProfileKeyCredentialRequestContext",
            &randomness,
        );
        let uid_bytes = uuid::Uuid::from(aci).into_bytes();
        let profile_key_struct =
            crypto::profile_key_struct::ProfileKeyStruct::new(profile_key.bytes, uid_bytes);

        let commitment_with_secret_nonce =
            crypto::profile_key_commitment::CommitmentWithSecretNonce::new(
                profile_key_struct,
                uid_bytes,
            );

        let key_pair = crypto::profile_key_credential_request::KeyPair::generate(&mut sho);
        let ciphertext_with_secret_nonce = key_pair.encrypt(profile_key_struct, &mut sho);

        let proof = crypto::proofs::ProfileKeyCredentialRequestProof::new(
            key_pair,
            ciphertext_with_secret_nonce,
            commitment_with_secret_nonce,
            &mut sho,
        );

        api::profiles::ProfileKeyCredentialRequestContext {
            reserved: Default::default(),
            aci_bytes: uid_bytes,
            profile_key_bytes: profile_key_struct.bytes,
            key_pair,
            ciphertext_with_secret_nonce,
            proof,
        }
    }

    pub fn receive_expiring_profile_key_credential(
        &self,
        context: &api::profiles::ProfileKeyCredentialRequestContext,
        response: &api::profiles::ExpiringProfileKeyCredentialResponse,
        current_time: Timestamp,
    ) -> Result<api::profiles::ExpiringProfileKeyCredential, ZkGroupVerificationFailure> {
        response.proof.verify(
            self.expiring_profile_key_credentials_public_key,
            context.key_pair.get_public_key(),
            context.aci_bytes,
            context.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
            response.credential_expiration_time,
        )?;

        if response.credential_expiration_time % SECONDS_PER_DAY != 0 {
            return Err(ZkGroupVerificationFailure);
        }
        let days_remaining = response
            .credential_expiration_time
            .saturating_sub(current_time)
            / SECONDS_PER_DAY;
        if days_remaining == 0 || days_remaining > 7 {
            return Err(ZkGroupVerificationFailure);
        }

        let credential = context
            .key_pair
            .decrypt_blinded_expiring_profile_key_credential(response.blinded_credential);

        Ok(api::profiles::ExpiringProfileKeyCredential {
            version: Default::default(),
            credential,
            aci_bytes: context.aci_bytes,
            profile_key_bytes: context.profile_key_bytes,
            credential_expiration_time: response.credential_expiration_time,
        })
    }

    pub fn create_expiring_profile_key_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        expiring_profile_key_credential: api::profiles::ExpiringProfileKeyCredential,
    ) -> api::profiles::ExpiringProfileKeyCredentialPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220508_Random_ServerPublicParams_CreateExpiringProfileKeyCredentialPresentation",
            &randomness,
        );

        let uid_enc_key_pair = group_secret_params.uid_enc_key_pair;
        let profile_key_enc_key_pair = group_secret_params.profile_key_enc_key_pair;
        let credentials_public_key = self.expiring_profile_key_credentials_public_key;

        let uid = expiring_profile_key_credential.aci();
        let uuid_ciphertext = group_secret_params.encrypt_service_id(uid.into());
        let profile_key_ciphertext = group_secret_params
            .encrypt_profile_key_bytes(expiring_profile_key_credential.profile_key_bytes, uid);

        let proof = crypto::proofs::ExpiringProfileKeyCredentialPresentationProof::new(
            uid_enc_key_pair,
            profile_key_enc_key_pair,
            credentials_public_key,
            expiring_profile_key_credential.credential,
            uuid_ciphertext.ciphertext,
            profile_key_ciphertext.ciphertext,
            expiring_profile_key_credential.aci_bytes,
            expiring_profile_key_credential.profile_key_bytes,
            &mut sho,
        );

        api::profiles::ExpiringProfileKeyCredentialPresentation {
            version: [PRESENTATION_VERSION_3],
            proof,
            uid_enc_ciphertext: uuid_ciphertext.ciphertext,
            profile_key_enc_ciphertext: profile_key_ciphertext.ciphertext,
            credential_expiration_time: expiring_profile_key_credential.credential_expiration_time,
        }
    }

    pub fn create_receipt_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        receipt_serial_bytes: ReceiptSerialBytes,
    ) -> api::receipts::ReceiptCredentialRequestContext {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20210919_Random_ServerPublicParams_CreateReceiptCredentialRequestContext",
            &randomness,
        );

        let key_pair = crypto::receipt_credential_request::KeyPair::generate(&mut sho);
        let ciphertext_with_secret_nonce = key_pair.encrypt(receipt_serial_bytes, &mut sho);

        api::receipts::ReceiptCredentialRequestContext {
            reserved: Default::default(),
            receipt_serial_bytes,
            key_pair,
            ciphertext_with_secret_nonce,
        }
    }

    pub fn receive_receipt_credential(
        &self,
        context: &api::receipts::ReceiptCredentialRequestContext,
        response: &api::receipts::ReceiptCredentialResponse,
    ) -> Result<api::receipts::ReceiptCredential, ZkGroupVerificationFailure> {
        let receipt_struct = crypto::receipt_struct::ReceiptStruct::new(
            context.receipt_serial_bytes,
            response.receipt_expiration_time,
            response.receipt_level,
        );
        response.proof.verify(
            self.receipt_credentials_public_key,
            context.key_pair.get_public_key(),
            context.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
            receipt_struct,
        )?;
        let credential = context
            .key_pair
            .decrypt_blinded_receipt_credential(response.blinded_credential);
        Ok(api::receipts::ReceiptCredential {
            reserved: Default::default(),
            credential,
            receipt_expiration_time: response.receipt_expiration_time,
            receipt_level: response.receipt_level,
            receipt_serial_bytes: context.receipt_serial_bytes,
        })
    }

    pub fn create_receipt_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        receipt_credential: &api::receipts::ReceiptCredential,
    ) -> api::receipts::ReceiptCredentialPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20210919_Random_ServerPublicParams_CreateReceiptCredentialPresentation",
            &randomness,
        );
        let proof = crypto::proofs::ReceiptCredentialPresentationProof::new(
            self.receipt_credentials_public_key,
            receipt_credential.credential,
            &mut sho,
        );
        api::receipts::ReceiptCredentialPresentation {
            reserved: Default::default(),
            proof,
            receipt_expiration_time: receipt_credential.receipt_expiration_time,
            receipt_level: receipt_credential.receipt_level,
            receipt_serial_bytes: receipt_credential.receipt_serial_bytes,
        }
    }
}
