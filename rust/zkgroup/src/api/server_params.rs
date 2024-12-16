//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::serialization::{ReservedByte, VersionByte};
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::{api, crypto};

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct ServerSecretParams {
    reserved: ReservedByte,
    // Now unused
    auth_credentials_key_pair: crypto::credentials::KeyPair<crypto::credentials::AuthCredential>,

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

    // Now unused
    auth_credentials_with_pni_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::AuthCredentialWithPni>,

    pub(crate) generic_credential_key_pair: zkcredential::credentials::CredentialKeyPair,
    pub(crate) endorsement_key_pair: zkcredential::endorsements::ServerRootKeyPair,
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct ServerPublicParams {
    reserved: ReservedByte,
    // Now unused
    auth_credentials_public_key: crypto::credentials::PublicKey,

    // Now unused
    pub(crate) profile_key_credentials_public_key: crypto::credentials::PublicKey,

    sig_public_key: crypto::signature::PublicKey,
    receipt_credentials_public_key: crypto::credentials::PublicKey,

    // Now unused
    pni_credentials_public_key: crypto::credentials::PublicKey,

    expiring_profile_key_credentials_public_key: crypto::credentials::PublicKey,

    // Now unused
    auth_credentials_with_pni_public_key: crypto::credentials::PublicKey,

    pub(crate) generic_credential_public_key: zkcredential::credentials::CredentialPublicKey,
    pub(crate) endorsement_public_key: zkcredential::endorsements::ServerRootPublicKey,
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
        let generic_credential_key_pair =
            zkcredential::credentials::CredentialKeyPair::generate(randomness);
        let endorsement_key_pair =
            zkcredential::endorsements::ServerRootKeyPair::generate(randomness);

        Self {
            reserved: Default::default(),
            auth_credentials_key_pair,
            profile_key_credentials_key_pair,
            sig_key_pair,
            receipt_credentials_key_pair,
            pni_credentials_key_pair,
            expiring_profile_key_credentials_key_pair,
            auth_credentials_with_pni_key_pair,
            generic_credential_key_pair,
            endorsement_key_pair,
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
            generic_credential_public_key: self.generic_credential_key_pair.public_key().clone(),
            endorsement_public_key: self.endorsement_key_pair.public_key().clone(),
        }
    }

    pub fn sign(&self, randomness: RandomnessBytes, message: &[u8]) -> NotarySignatureBytes {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_Sign",
            &randomness,
        );
        self.sig_key_pair.sign(message, &mut sho)
    }

    /// Checks that `current_time` is within the validity window defined by
    /// `redemption_time`.
    ///
    /// All times are relative to SystemTime::UNIX_EPOCH,
    /// but we don't actually use SystemTime because it's too small on 32-bit Linux.
    pub(crate) fn check_auth_credential_redemption_time(
        redemption_time: Timestamp,
        current_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let acceptable_start_time = redemption_time
            .checked_sub_seconds(SECONDS_PER_DAY)
            .ok_or(ZkGroupVerificationFailure)?;
        let acceptable_end_time = redemption_time
            .checked_add_seconds(2 * SECONDS_PER_DAY)
            .ok_or(ZkGroupVerificationFailure)?;

        if !(acceptable_start_time..=acceptable_end_time).contains(&current_time) {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(())
    }

    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AnyAuthCredentialPresentation,
        current_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        Self::check_auth_credential_redemption_time(
            presentation.get_redemption_time(),
            current_time,
        )?;

        match presentation {
            api::auth::AnyAuthCredentialPresentation::V4(presentation) => {
                presentation.verify(self, &group_public_params, presentation.redemption_time())
            }
        }
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
        aci: libsignal_core::Aci,
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
            reserved: Default::default(),
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

    pub fn create_profile_key_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        aci: libsignal_core::Aci,
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

        if !response.credential_expiration_time.is_day_aligned() {
            return Err(ZkGroupVerificationFailure);
        }
        let days_remaining = response
            .credential_expiration_time
            .saturating_seconds_since(current_time)
            / SECONDS_PER_DAY;
        if days_remaining == 0 || days_remaining > 7 {
            return Err(ZkGroupVerificationFailure);
        }

        let credential = context
            .key_pair
            .decrypt_blinded_expiring_profile_key_credential(response.blinded_credential);

        Ok(api::profiles::ExpiringProfileKeyCredential {
            reserved: Default::default(),
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
            version: VersionByte,
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
