//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::api;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerSecretParams {
    pub(crate) reserved: ReservedBytes,
    pub(crate) auth_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::AuthCredential>,
    pub(crate) profile_key_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::ProfileKeyCredential>,
    sig_key_pair: crypto::signature::KeyPair,
    receipt_credentials_key_pair:
        crypto::credentials::KeyPair<crypto::credentials::ReceiptCredential>,
    pni_credentials_key_pair: crypto::credentials::KeyPair<crypto::credentials::PniCredential>,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ServerPublicParams {
    pub(crate) reserved: ReservedBytes,
    pub(crate) auth_credentials_public_key: crypto::credentials::PublicKey,
    pub(crate) profile_key_credentials_public_key: crypto::credentials::PublicKey,
    sig_public_key: crypto::signature::PublicKey,
    receipt_credentials_public_key: crypto::credentials::PublicKey,
    pni_credentials_public_key: crypto::credentials::PublicKey,
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

        Self {
            reserved: Default::default(),
            auth_credentials_key_pair,
            profile_key_credentials_key_pair,
            sig_key_pair,
            receipt_credentials_key_pair,
            pni_credentials_key_pair,
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
        }
    }

    pub fn sign(
        &self,
        randomness: RandomnessBytes,
        message: &[u8],
    ) -> Result<NotarySignatureBytes, ZkGroupError> {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_Sign",
            &randomness,
        );
        self.sig_key_pair.sign(message, &mut sho)
    }

    pub fn issue_auth_credential(
        &self,
        randomness: RandomnessBytes,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
    ) -> api::auth::AuthCredentialResponse {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_IssueAuthCredential",
            &randomness,
        );

        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
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

    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::auth::AuthCredentialPresentation,
    ) -> Result<(), ZkGroupError> {
        presentation.proof.verify(
            self.auth_credentials_key_pair,
            group_public_params.uid_enc_public_key,
            presentation.ciphertext,
            presentation.redemption_time,
        )
    }

    pub fn verify_profile_key_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::profiles::ProfileKeyCredentialPresentation,
    ) -> Result<(), ZkGroupError> {
        let credentials_key_pair = self.profile_key_credentials_key_pair;
        let uid_enc_public_key = group_public_params.uid_enc_public_key;
        let profile_key_enc_public_key = group_public_params.profile_key_enc_public_key;

        presentation.proof.verify(
            credentials_key_pair,
            presentation.uid_enc_ciphertext,
            uid_enc_public_key,
            presentation.profile_key_enc_ciphertext,
            profile_key_enc_public_key,
        )
    }

    pub fn verify_pni_credential_presentation(
        &self,
        group_public_params: api::groups::GroupPublicParams,
        presentation: &api::profiles::PniCredentialPresentation,
    ) -> Result<(), ZkGroupError> {
        let credentials_key_pair = self.pni_credentials_key_pair;
        let uid_enc_public_key = group_public_params.uid_enc_public_key;
        let profile_key_enc_public_key = group_public_params.profile_key_enc_public_key;

        presentation.proof.verify(
            credentials_key_pair,
            presentation.aci_enc_ciphertext,
            uid_enc_public_key,
            presentation.profile_key_enc_ciphertext,
            profile_key_enc_public_key,
            presentation.pni_enc_ciphertext,
        )
    }

    pub fn issue_profile_key_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::profiles::ProfileKeyCredentialRequest,
        uid_bytes: UidBytes,
        commitment: api::profiles::ProfileKeyCommitment,
    ) -> Result<api::profiles::ProfileKeyCredentialResponse, ZkGroupError> {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerSecretParams_IssueProfileKeyCredential",
            &randomness,
        );

        request.proof.verify(
            request.public_key,
            request.ciphertext,
            commitment.commitment,
        )?;

        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        let blinded_credential_with_secret_nonce = self
            .profile_key_credentials_key_pair
            .create_blinded_profile_key_credential(
                uid,
                request.public_key,
                request.ciphertext,
                &mut sho,
            );

        let proof = crypto::proofs::ProfileKeyCredentialIssuanceProof::new(
            self.profile_key_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            uid,
            &mut sho,
        );

        Ok(api::profiles::ProfileKeyCredentialResponse {
            reserved: Default::default(),
            blinded_credential: blinded_credential_with_secret_nonce
                .get_blinded_profile_key_credential(),
            proof,
        })
    }

    pub fn issue_pni_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::profiles::ProfileKeyCredentialRequest,
        uid_bytes: UidBytes,
        pni_bytes: UidBytes,
        commitment: api::profiles::ProfileKeyCommitment,
    ) -> Result<api::profiles::PniCredentialResponse, ZkGroupError> {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20211111_Random_ServerSecretParams_IssuePniCredential",
            &randomness,
        );

        request.proof.verify(
            request.public_key,
            request.ciphertext,
            commitment.commitment,
        )?;

        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        let pni = crypto::uid_struct::UidStruct::new(pni_bytes);
        let blinded_credential_with_secret_nonce =
            self.pni_credentials_key_pair.create_blinded_pni_credential(
                uid,
                pni,
                request.public_key,
                request.ciphertext,
                &mut sho,
            );

        let proof = crypto::proofs::PniCredentialIssuanceProof::new(
            self.pni_credentials_key_pair,
            request.public_key,
            request.ciphertext,
            blinded_credential_with_secret_nonce,
            uid,
            pni,
            &mut sho,
        );

        Ok(api::profiles::PniCredentialResponse {
            reserved: Default::default(),
            blinded_credential: blinded_credential_with_secret_nonce.get_blinded_pni_credential(),
            proof,
        })
    }

    pub fn issue_receipt_credential(
        &self,
        randomness: RandomnessBytes,
        request: &api::receipts::ReceiptCredentialRequest,
        receipt_expiration_time: ReceiptExpirationTime,
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
    ) -> Result<(), ZkGroupError> {
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
    ) -> Result<(), ZkGroupError> {
        self.sig_public_key.verify(message, signature)
    }

    pub fn receive_auth_credential(
        &self,
        uid_bytes: UidBytes,
        redemption_time: RedemptionTime,
        response: &api::auth::AuthCredentialResponse,
    ) -> Result<api::auth::AuthCredential, ZkGroupError> {
        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
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

    pub fn create_auth_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        auth_credential: api::auth::AuthCredential,
    ) -> api::auth::AuthCredentialPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateAuthCredentialPresentation",
            &randomness,
        );

        let uuid_ciphertext = group_secret_params.encrypt_uid_struct(auth_credential.uid);

        let proof = crypto::proofs::AuthCredentialPresentationProof::new(
            self.auth_credentials_public_key,
            group_secret_params.uid_enc_key_pair,
            auth_credential.credential,
            auth_credential.uid,
            uuid_ciphertext.ciphertext,
            auth_credential.redemption_time,
            &mut sho,
        );

        api::auth::AuthCredentialPresentation {
            reserved: Default::default(),
            proof,
            ciphertext: uuid_ciphertext.ciphertext,
            redemption_time: auth_credential.redemption_time,
        }
    }

    pub fn create_profile_key_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        uid_bytes: UidBytes,
        profile_key: api::profiles::ProfileKey,
    ) -> api::profiles::ProfileKeyCredentialRequestContext {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateProfileKeyCredentialRequestContext",
            &randomness,
        );
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
            uid_bytes,
            profile_key_bytes: profile_key_struct.bytes,
            key_pair,
            ciphertext_with_secret_nonce,
            proof,
        }
    }

    pub fn create_pni_credential_request_context(
        &self,
        randomness: RandomnessBytes,
        aci_bytes: UidBytes,
        pni_bytes: UidBytes,
        profile_key: api::profiles::ProfileKey,
    ) -> api::profiles::PniCredentialRequestContext {
        // We want to provide an encryption of the profile key and prove that it matches the
        // ProfileKeyCommitment in *exactly* the same way as a non-PNI request, so just invoke that
        // and then add the PNI to the result.
        let profile_key_request_context =
            self.create_profile_key_credential_request_context(randomness, aci_bytes, profile_key);
        api::profiles::PniCredentialRequestContext {
            reserved: Default::default(),
            aci_bytes,
            pni_bytes,
            profile_key_bytes: profile_key_request_context.profile_key_bytes,
            key_pair: profile_key_request_context.key_pair,
            ciphertext_with_secret_nonce: profile_key_request_context.ciphertext_with_secret_nonce,
            proof: profile_key_request_context.proof,
        }
    }

    pub fn receive_profile_key_credential(
        &self,
        context: &api::profiles::ProfileKeyCredentialRequestContext,
        response: &api::profiles::ProfileKeyCredentialResponse,
    ) -> Result<api::profiles::ProfileKeyCredential, ZkGroupError> {
        response.proof.verify(
            self.profile_key_credentials_public_key,
            context.key_pair.get_public_key(),
            context.uid_bytes,
            context.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
        )?;

        let credential = context
            .key_pair
            .decrypt_blinded_profile_key_credential(response.blinded_credential);

        Ok(api::profiles::ProfileKeyCredential {
            reserved: Default::default(),
            credential,
            uid_bytes: context.uid_bytes,
            profile_key_bytes: context.profile_key_bytes,
        })
    }

    pub fn receive_pni_credential(
        &self,
        context: &api::profiles::PniCredentialRequestContext,
        response: &api::profiles::PniCredentialResponse,
    ) -> Result<api::profiles::PniCredential, ZkGroupError> {
        response.proof.verify(
            self.pni_credentials_public_key,
            context.key_pair.get_public_key(),
            context.aci_bytes,
            context.pni_bytes,
            context.ciphertext_with_secret_nonce.get_ciphertext(),
            response.blinded_credential,
        )?;

        let credential = context
            .key_pair
            .decrypt_blinded_pni_credential(response.blinded_credential);

        Ok(api::profiles::PniCredential {
            reserved: Default::default(),
            credential,
            aci_bytes: context.aci_bytes,
            pni_bytes: context.pni_bytes,
            profile_key_bytes: context.profile_key_bytes,
        })
    }

    pub fn create_profile_key_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        profile_key_credential: api::profiles::ProfileKeyCredential,
    ) -> api::profiles::ProfileKeyCredentialPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateProfileKeyCredentialPresentation",
            &randomness,
        );

        let uid_enc_key_pair = group_secret_params.uid_enc_key_pair;
        let profile_key_enc_key_pair = group_secret_params.profile_key_enc_key_pair;
        let credentials_public_key = self.profile_key_credentials_public_key;

        let uuid_ciphertext = group_secret_params.encrypt_uuid(profile_key_credential.uid_bytes);
        let profile_key_ciphertext = group_secret_params.encrypt_profile_key_bytes(
            profile_key_credential.profile_key_bytes,
            profile_key_credential.uid_bytes,
        );

        let proof = crypto::proofs::ProfileKeyCredentialPresentationProof::new(
            uid_enc_key_pair,
            profile_key_enc_key_pair,
            credentials_public_key,
            profile_key_credential.credential,
            uuid_ciphertext.ciphertext,
            profile_key_ciphertext.ciphertext,
            profile_key_credential.uid_bytes,
            profile_key_credential.profile_key_bytes,
            &mut sho,
        );

        api::profiles::ProfileKeyCredentialPresentation {
            reserved: Default::default(),
            proof,
            uid_enc_ciphertext: uuid_ciphertext.ciphertext,
            profile_key_enc_ciphertext: profile_key_ciphertext.ciphertext,
        }
    }

    pub fn create_pni_credential_presentation(
        &self,
        randomness: RandomnessBytes,
        group_secret_params: api::groups::GroupSecretParams,
        pni_credential: api::profiles::PniCredential,
    ) -> api::profiles::PniCredentialPresentation {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20211111_Random_ServerPublicParams_CreatePniCredentialPresentation",
            &randomness,
        );

        let uid_enc_key_pair = group_secret_params.uid_enc_key_pair;
        let profile_key_enc_key_pair = group_secret_params.profile_key_enc_key_pair;
        let credentials_public_key = self.pni_credentials_public_key;

        let aci_ciphertext = group_secret_params.encrypt_uuid(pni_credential.aci_bytes);
        let pni_ciphertext = group_secret_params.encrypt_uuid(pni_credential.pni_bytes);
        let profile_key_ciphertext = group_secret_params
            .encrypt_profile_key_bytes(pni_credential.profile_key_bytes, pni_credential.aci_bytes);

        let proof = crypto::proofs::PniCredentialPresentationProof::new(
            uid_enc_key_pair,
            profile_key_enc_key_pair,
            credentials_public_key,
            pni_credential.credential,
            aci_ciphertext.ciphertext,
            pni_ciphertext.ciphertext,
            profile_key_ciphertext.ciphertext,
            pni_credential.aci_bytes,
            pni_credential.pni_bytes,
            pni_credential.profile_key_bytes,
            &mut sho,
        );

        api::profiles::PniCredentialPresentation {
            reserved: Default::default(),
            proof,
            aci_enc_ciphertext: aci_ciphertext.ciphertext,
            pni_enc_ciphertext: pni_ciphertext.ciphertext,
            profile_key_enc_ciphertext: profile_key_ciphertext.ciphertext,
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
    ) -> Result<api::receipts::ReceiptCredential, ZkGroupError> {
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
