//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Provides BackupAuthCredential and related types.
//!
//! BackupAuthCredential is a MAC over:
//! - a backup-id (a 16-byte value deterministically derived from the client's master key, blinded at issuance, revealed for verification)
//! - a timestamp, truncated to day granularity (chosen by the chat server at issuance, passed publicly to the verifying server)
//! - a receipt level (chosen by the chat server at issuance, passed publicly to the verifying server)
//!
//! The BackupAuthCredentialPresentation includes the public backup-id in the clear for verification
//!
//! The BackupAuthCredential has the additional constraint that it should be deterministically reproducible. Rather than a randomly
//! seeded blinding key pair, the key pair is derived from, you guessed it, the client's master key.

use curve25519_dalek::ristretto::RistrettoPoint;
use hkdf::Hkdf;
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use poksho::ShoApi;

use crate::common::sho::Sho;
use crate::common::simple_types::*;
use crate::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use crate::{ZkGroupVerificationFailure, SECONDS_PER_DAY};

#[derive(Serialize, Deserialize, Clone, Copy)]
struct BackupIdPoint(RistrettoPoint);

impl BackupIdPoint {
    fn new(backup_id: &[u8; 16]) -> Self {
        Self(Sho::new(b"20231003_Signal_BackupId", backup_id).get_point())
    }
}

impl zkcredential::attributes::RevealedAttribute for BackupIdPoint {
    fn as_point(&self) -> RistrettoPoint {
        self.0
    }
}

const CREDENTIAL_LABEL: &[u8] = b"20231003_Signal_BackupAuthCredential";

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialRequestContext {
    reserved: ReservedBytes,
    blinded_backup_id: zkcredential::issuance::blind::BlindedPoint,
    // A 16-byte identifier derived from the the backup-key
    backup_id: [u8; 16],
    key_pair: zkcredential::issuance::blind::BlindingKeyPair,
}

impl BackupAuthCredentialRequestContext {
    /// Create a BackupAuthCredentialRequestContext
    ///
    /// # Arguments
    /// * backup_key - A 32-byte key derived from the client master key
    /// * uuid - The client's account identifier
    pub fn new(backup_key: &[u8; 32], uuid: &uuid::Uuid) -> Self {
        let uuid_bytes = uuid.as_bytes();

        // derive the backup-id (blinded in the issuance request, revealed at verification)
        let mut backup_id = [0u8; 16];
        Hkdf::<Sha256>::new(Some(uuid_bytes), backup_key)
            .expand(b"20231003_Signal_Backups_GenerateBackupId", &mut backup_id)
            .expect("should expand");

        let mut sho = poksho::ShoHmacSha256::new(b"20231003_Signal_BackupAuthCredentialRequest");
        sho.absorb_and_ratchet(uuid_bytes);
        sho.absorb_and_ratchet(backup_key);

        let key_pair = zkcredential::issuance::blind::BlindingKeyPair::generate(&mut sho);

        let blinded_backup_id = key_pair
            .blind(&BackupIdPoint::new(&backup_id), &mut sho)
            .into();

        Self {
            reserved: [0],
            blinded_backup_id,
            backup_id,
            key_pair,
        }
    }

    pub fn get_request(&self) -> BackupAuthCredentialRequest {
        BackupAuthCredentialRequest {
            reserved: [0],
            blinded_backup_id: self.blinded_backup_id,
            public_key: *self.key_pair.public_key(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialRequest {
    reserved: ReservedBytes,
    blinded_backup_id: zkcredential::issuance::blind::BlindedPoint,
    public_key: zkcredential::issuance::blind::BlindingPublicKey,
}

impl BackupAuthCredentialRequest {
    pub fn issue(
        &self,
        redemption_time: Timestamp,
        receipt_level: ReceiptLevel,
        params: &GenericServerSecretParams,
        randomness: RandomnessBytes,
    ) -> BackupAuthCredentialResponse {
        BackupAuthCredentialResponse {
            reserved: [0],
            redemption_time,
            receipt_level,
            blinded_credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&redemption_time)
                .add_public_attribute(&receipt_level)
                .add_blinded_revealed_attribute(&self.blinded_backup_id)
                .issue(&params.credential_key, &self.public_key, randomness),
        }
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialResponse {
    reserved: ReservedBytes,
    redemption_time: Timestamp,
    receipt_level: ReceiptLevel,
    blinded_credential: zkcredential::issuance::blind::BlindedIssuanceProof,
}

impl BackupAuthCredentialRequestContext {
    pub fn receive(
        self,
        response: BackupAuthCredentialResponse,
        params: &GenericServerPublicParams,
        expected_receipt_level: ReceiptLevel,
    ) -> Result<BackupAuthCredential, ZkGroupVerificationFailure> {
        if response.redemption_time % SECONDS_PER_DAY != 0 {
            return Err(ZkGroupVerificationFailure);
        }

        if response.receipt_level != expected_receipt_level {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(BackupAuthCredential {
            reserved: [0],
            redemption_time: response.redemption_time,
            receipt_level: response.receipt_level,
            credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&response.redemption_time)
                .add_public_attribute(&expected_receipt_level)
                .add_blinded_revealed_attribute(&self.blinded_backup_id)
                .verify(
                    &params.credential_key,
                    &self.key_pair,
                    response.blinded_credential,
                )
                .map_err(|_| ZkGroupVerificationFailure)?,
            backup_id: self.backup_id,
        })
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredential {
    reserved: ReservedBytes,
    redemption_time: Timestamp,
    receipt_level: ReceiptLevel,
    credential: zkcredential::credentials::Credential,
    backup_id: [u8; 16],
}

impl BackupAuthCredential {
    pub fn present(
        &self,
        server_params: &GenericServerPublicParams,
        randomness: RandomnessBytes,
    ) -> BackupAuthCredentialPresentation {
        BackupAuthCredentialPresentation {
            reserved: [0],
            redemption_time: self.redemption_time,
            receipt_level: self.receipt_level,
            backup_id: self.backup_id,
            proof: zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
                .add_revealed_attribute(&BackupIdPoint::new(&self.backup_id))
                .present(&server_params.credential_key, &self.credential, randomness),
        }
    }

    pub fn backup_id(&self) -> [u8; 16] {
        self.backup_id
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialPresentation {
    reserved: ReservedBytes,
    receipt_level: ReceiptLevel,
    redemption_time: Timestamp,
    proof: zkcredential::presentation::PresentationProof,
    backup_id: [u8; 16],
}

impl BackupAuthCredentialPresentation {
    pub fn verify(
        &self,
        current_time_in_seconds: Timestamp,
        server_params: &GenericServerSecretParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let acceptable_start_time = self
            .redemption_time
            .checked_sub(SECONDS_PER_DAY)
            .ok_or(ZkGroupVerificationFailure)?;
        let acceptable_end_time = self
            .redemption_time
            .checked_add(2 * SECONDS_PER_DAY)
            .ok_or(ZkGroupVerificationFailure)?;

        if !(acceptable_start_time..=acceptable_end_time).contains(&current_time_in_seconds) {
            return Err(ZkGroupVerificationFailure);
        }

        zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
            .add_public_attribute(&self.redemption_time)
            .add_public_attribute(&self.receipt_level)
            .add_revealed_attribute(&BackupIdPoint::new(&self.backup_id))
            .verify(&server_params.credential_key, &self.proof)
            .map_err(|_| ZkGroupVerificationFailure)
    }

    pub fn receipt_level(&self) -> ReceiptLevel {
        self.receipt_level
    }

    pub fn backup_id(&self) -> [u8; 16] {
        self.backup_id
    }
}

#[cfg(test)]
mod tests {
    use crate::backups::auth_credential::GenericServerSecretParams;
    use crate::backups::{
        BackupAuthCredential, BackupAuthCredentialPresentation, BackupAuthCredentialRequestContext,
    };
    use crate::{RandomnessBytes, Timestamp, RANDOMNESS_LEN, SECONDS_PER_DAY};

    const DAY_ALIGNED_TIMESTAMP: Timestamp = 1681344000; // 2023-04-13 00:00:00 UTC
    const KEY: [u8; 32] = [0x42u8; 32];
    const ACI: uuid::Uuid = uuid::uuid!("c0fc16e4-bae5-4343-9f0d-e7ecf4251343");
    const SERVER_SECRET_RAND: RandomnessBytes = [0xA0; RANDOMNESS_LEN];
    const ISSUE_RAND: RandomnessBytes = [0xA1; RANDOMNESS_LEN];
    const PRESENT_RAND: RandomnessBytes = [0xA2; RANDOMNESS_LEN];

    fn server_secret_params() -> GenericServerSecretParams {
        GenericServerSecretParams::generate(SERVER_SECRET_RAND)
    }

    fn generate_credential(redemption_time: Timestamp) -> BackupAuthCredential {
        let receipt_level = 10;

        // client generated materials; issuance request
        let request_context = BackupAuthCredentialRequestContext::new(&KEY, &ACI);
        let request = request_context.get_request();

        // server generated materials; issuance request -> issuance response
        let blinded_credential = request.issue(
            redemption_time,
            receipt_level,
            &server_secret_params(),
            ISSUE_RAND,
        );

        // client generated materials; issuance response -> redemption request
        let server_public_params = server_secret_params().get_public_params();
        request_context
            .receive(blinded_credential, &server_public_params, receipt_level)
            .expect("credential should be valid")
    }

    #[test]
    fn test_server_verify_expiration() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);

        presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect("presentation should be valid");

        presentation
            .verify(
                DAY_ALIGNED_TIMESTAMP - SECONDS_PER_DAY - 1,
                &server_secret_params(),
            )
            .expect_err("credential should not be valid 24h before redemption time");
        presentation
            .verify(
                DAY_ALIGNED_TIMESTAMP + 2 * SECONDS_PER_DAY + 1,
                &server_secret_params(),
            )
            .expect_err("credential should not be valid after expiration (2 days later)");
    }

    #[test]
    fn test_server_verify_wrong_backup_id() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let valid_presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);
        let invalid_presentation = BackupAuthCredentialPresentation {
            backup_id: *b"a fake backup-id",
            ..valid_presentation
        };
        invalid_presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect_err("credential should not be valid with different backup-id");
    }

    #[test]
    fn test_server_verify_wrong_redemption() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let valid_presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);
        let invalid_presentation = BackupAuthCredentialPresentation {
            redemption_time: DAY_ALIGNED_TIMESTAMP + 1,
            ..valid_presentation
        };
        invalid_presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect_err("credential should not be valid with altered redemption_time");
    }

    #[test]
    fn test_server_verify_wrong_receipt_level() {
        let credential = generate_credential(DAY_ALIGNED_TIMESTAMP);
        let valid_presentation =
            credential.present(&server_secret_params().get_public_params(), PRESENT_RAND);
        let invalid_presentation = BackupAuthCredentialPresentation {
            receipt_level: 999,
            ..valid_presentation
        };
        invalid_presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect_err("credential should not be valid with wrong receipt");
    }

    #[test]
    fn test_client_enforces_timestamp_granularity() {
        let redemption_time: Timestamp = DAY_ALIGNED_TIMESTAMP + 60 * 60; // not on a day boundary!

        let request_context = BackupAuthCredentialRequestContext::new(&KEY, &ACI);
        let request = request_context.get_request();
        let blinded_credential =
            request.issue(redemption_time, 1, &server_secret_params(), ISSUE_RAND);
        assert!(
            request_context
                .receive(
                    blinded_credential,
                    &server_secret_params().get_public_params(),
                    1
                )
                .is_err(),
            "client should require that timestamp is on a day boundary"
        );
    }

    #[test]
    fn test_client_enforces_receipt_level() {
        let request_context = BackupAuthCredentialRequestContext::new(&KEY, &ACI);
        let request = request_context.get_request();
        let blinded_credential = request.issue(
            DAY_ALIGNED_TIMESTAMP,
            1,
            &server_secret_params(),
            ISSUE_RAND,
        );
        assert!(
            request_context
                .receive(
                    blinded_credential,
                    &server_secret_params().get_public_params(),
                    2
                )
                .is_err(),
            "client should require receipt level 2"
        );
    }
}
