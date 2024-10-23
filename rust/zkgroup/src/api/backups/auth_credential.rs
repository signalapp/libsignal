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

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use partial_default::PartialDefault;
use poksho::ShoApi;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::common::sho::Sho;
use crate::common::simple_types::*;
use crate::generic_server_params::{GenericServerPublicParams, GenericServerSecretParams};
use crate::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure, SECONDS_PER_DAY};

#[derive(Serialize, Deserialize, Clone, Copy)]
struct BackupIdPoint(RistrettoPoint);

impl BackupIdPoint {
    fn new(backup_id: &libsignal_account_keys::BackupId) -> Self {
        Self(Sho::new(b"20231003_Signal_BackupId", &backup_id.0).get_point())
    }
}

impl zkcredential::attributes::RevealedAttribute for BackupIdPoint {
    fn as_point(&self) -> RistrettoPoint {
        self.0
    }
}

const CREDENTIAL_LABEL: &[u8] = b"20231003_Signal_BackupAuthCredential";

// We make sure we serialize BackupLevel and BackupType with plenty of room to expand to other u64
// values later. But since they fit in a byte today, we stick to just a u8 in the in-memory and
// bridge representation.

#[derive(
    Copy,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialDefault,
    Debug,
    num_enum::TryFromPrimitive,
)]
#[serde(into = "u64", try_from = "u64")]
#[repr(u8)]
pub enum BackupLevel {
    #[partial_default]
    Free = 200,
    Paid = 201,
}

impl From<BackupLevel> for u64 {
    fn from(backup_level: BackupLevel) -> Self {
        backup_level as u64
    }
}

impl TryFrom<u64> for BackupLevel {
    // Unfortunately u8::try_from and TryFromPrimitive have different Error types.
    // But we shouldn't be passing invalid BackupLevels anyway.
    type Error = ZkGroupDeserializationFailure;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .ok()
            .and_then(|v| BackupLevel::try_from(v).ok())
            .ok_or(ZkGroupDeserializationFailure::new::<Self>())
    }
}

#[derive(
    Copy,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialDefault,
    Debug,
    num_enum::TryFromPrimitive,
)]
#[serde(into = "u64", try_from = "u64")]
#[repr(u8)]
pub enum BackupCredentialType {
    #[partial_default]
    Messages = 1,
    Media = 2,
}

impl From<BackupCredentialType> for u64 {
    fn from(credential_type: BackupCredentialType) -> Self {
        credential_type as u64
    }
}

impl TryFrom<u64> for BackupCredentialType {
    // Unfortunately u8::try_from and TryFromPrimitive have different Error types.
    // But we shouldn't be passing invalid BackupTypes anyway.
    type Error = ZkGroupDeserializationFailure;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .ok()
            .and_then(|v| BackupCredentialType::try_from(v).ok())
            .ok_or(ZkGroupDeserializationFailure::new::<Self>())
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialRequestContext {
    reserved: ReservedByte,
    blinded_backup_id: zkcredential::issuance::blind::BlindedPoint,
    backup_id: libsignal_account_keys::BackupId,
    key_pair: zkcredential::issuance::blind::BlindingKeyPair,
}

impl BackupAuthCredentialRequestContext {
    pub fn new<const VERSION: u8>(
        backup_key: &libsignal_account_keys::BackupKey<VERSION>,
        aci: libsignal_core::Aci,
    ) -> Self {
        // derive the backup-id (blinded in the issuance request, revealed at verification)
        let backup_id = backup_key.derive_backup_id(&aci);

        let mut sho = poksho::ShoHmacSha256::new(b"20231003_Signal_BackupAuthCredentialRequest");
        sho.absorb_and_ratchet(uuid::Uuid::from(aci).as_bytes());
        sho.absorb_and_ratchet(&backup_key.0);

        let key_pair = zkcredential::issuance::blind::BlindingKeyPair::generate(&mut sho);

        let blinded_backup_id = key_pair
            .blind(&BackupIdPoint::new(&backup_id), &mut sho)
            .into();

        Self {
            reserved: Default::default(),
            blinded_backup_id,
            backup_id,
            key_pair,
        }
    }

    pub fn get_request(&self) -> BackupAuthCredentialRequest {
        BackupAuthCredentialRequest {
            reserved: Default::default(),
            blinded_backup_id: self.blinded_backup_id,
            public_key: *self.key_pair.public_key(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialRequest {
    reserved: ReservedByte,
    blinded_backup_id: zkcredential::issuance::blind::BlindedPoint,
    public_key: zkcredential::issuance::blind::BlindingPublicKey,
}

impl BackupAuthCredentialRequest {
    pub fn issue(
        &self,
        redemption_time: Timestamp,
        backup_level: BackupLevel,
        credential_type: BackupCredentialType,
        params: &GenericServerSecretParams,
        randomness: RandomnessBytes,
    ) -> BackupAuthCredentialResponse {
        BackupAuthCredentialResponse {
            reserved: Default::default(),
            redemption_time,
            backup_level,
            credential_type,
            blinded_credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&redemption_time)
                .add_public_attribute(&u64::from(backup_level))
                .add_public_attribute(&u64::from(credential_type))
                .add_blinded_revealed_attribute(&self.blinded_backup_id)
                .issue(&params.credential_key, &self.public_key, randomness),
        }
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialResponse {
    reserved: ReservedByte,
    // In theory, we don't need to store this (AuthCredentialResponse doesn't),
    // because the redemption time is also passed *outside* the response by chat-server.
    // But that would change the format.
    redemption_time: Timestamp,
    backup_level: BackupLevel,
    credential_type: BackupCredentialType,
    blinded_credential: zkcredential::issuance::blind::BlindedIssuanceProof,
}

impl BackupAuthCredentialRequestContext {
    pub fn receive(
        self,
        response: BackupAuthCredentialResponse,
        params: &GenericServerPublicParams,
        expected_redemption_time: Timestamp,
    ) -> Result<BackupAuthCredential, ZkGroupVerificationFailure> {
        if response.redemption_time != expected_redemption_time
            || !response.redemption_time.is_day_aligned()
        {
            return Err(ZkGroupVerificationFailure);
        }

        Ok(BackupAuthCredential {
            reserved: Default::default(),
            redemption_time: response.redemption_time,
            backup_level: response.backup_level,
            credential_type: response.credential_type,
            credential: zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
                .add_public_attribute(&response.redemption_time)
                .add_public_attribute(&u64::from(response.backup_level))
                .add_public_attribute(&u64::from(response.credential_type))
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
    reserved: ReservedByte,
    redemption_time: Timestamp,
    backup_level: BackupLevel,
    credential_type: BackupCredentialType,
    credential: zkcredential::credentials::Credential,
    backup_id: libsignal_account_keys::BackupId,
}

impl BackupAuthCredential {
    pub fn present(
        &self,
        server_params: &GenericServerPublicParams,
        randomness: RandomnessBytes,
    ) -> BackupAuthCredentialPresentation {
        BackupAuthCredentialPresentation {
            version: Default::default(),
            redemption_time: self.redemption_time,
            backup_level: self.backup_level,
            credential_type: self.credential_type,
            backup_id: self.backup_id,
            proof: zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
                .add_revealed_attribute(&BackupIdPoint::new(&self.backup_id))
                .present(&server_params.credential_key, &self.credential, randomness),
        }
    }

    pub fn backup_id(&self) -> libsignal_account_keys::BackupId {
        self.backup_id
    }

    pub fn backup_level(&self) -> BackupLevel {
        self.backup_level
    }

    pub fn credential_type(&self) -> BackupCredentialType {
        self.credential_type
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct BackupAuthCredentialPresentation {
    version: ReservedByte,
    backup_level: BackupLevel,
    credential_type: BackupCredentialType,
    redemption_time: Timestamp,
    proof: zkcredential::presentation::PresentationProof,
    backup_id: libsignal_account_keys::BackupId,
}

impl BackupAuthCredentialPresentation {
    pub fn verify(
        &self,
        current_time: Timestamp,
        server_params: &GenericServerSecretParams,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let acceptable_start_time = self
            .redemption_time
            .checked_sub_seconds(SECONDS_PER_DAY)
            .ok_or(ZkGroupVerificationFailure)?;
        let acceptable_end_time = self
            .redemption_time
            .checked_add_seconds(2 * SECONDS_PER_DAY)
            .ok_or(ZkGroupVerificationFailure)?;

        if !(acceptable_start_time..=acceptable_end_time).contains(&current_time) {
            return Err(ZkGroupVerificationFailure);
        }

        zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
            .add_public_attribute(&self.redemption_time)
            .add_public_attribute(&u64::from(self.backup_level))
            .add_public_attribute(&u64::from(self.credential_type))
            .add_revealed_attribute(&BackupIdPoint::new(&self.backup_id))
            .verify(&server_params.credential_key, &self.proof)
            .map_err(|_| ZkGroupVerificationFailure)
    }

    pub fn backup_level(&self) -> BackupLevel {
        self.backup_level
    }

    pub fn credential_type(&self) -> BackupCredentialType {
        self.credential_type
    }

    pub fn backup_id(&self) -> libsignal_account_keys::BackupId {
        self.backup_id
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::{common, RandomnessBytes, Timestamp, RANDOMNESS_LEN, SECONDS_PER_DAY};

    const DAY_ALIGNED_TIMESTAMP: Timestamp = Timestamp::from_epoch_seconds(1681344000); // 2023-04-13 00:00:00 UTC
    const KEY: libsignal_account_keys::BackupKey = libsignal_account_keys::BackupKey([0x42u8; 32]);
    const ACI: uuid::Uuid = uuid::uuid!("c0fc16e4-bae5-4343-9f0d-e7ecf4251343");
    const SERVER_SECRET_RAND: RandomnessBytes = [0xA0; RANDOMNESS_LEN];
    const ISSUE_RAND: RandomnessBytes = [0xA1; RANDOMNESS_LEN];
    const PRESENT_RAND: RandomnessBytes = [0xA2; RANDOMNESS_LEN];

    fn server_secret_params() -> GenericServerSecretParams {
        GenericServerSecretParams::generate(SERVER_SECRET_RAND)
    }

    fn generate_credential(redemption_time: Timestamp) -> BackupAuthCredential {
        // client generated materials; issuance request
        let request_context = BackupAuthCredentialRequestContext::new(&KEY, ACI.into());
        let request = request_context.get_request();

        // server generated materials; issuance request -> issuance response
        let blinded_credential = request.issue(
            redemption_time,
            BackupLevel::Free,
            BackupCredentialType::Messages,
            &server_secret_params(),
            ISSUE_RAND,
        );

        // client generated materials; issuance response -> redemption request
        let server_public_params = server_secret_params().get_public_params();
        request_context
            .receive(blinded_credential, &server_public_params, redemption_time)
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
                DAY_ALIGNED_TIMESTAMP.sub_seconds(SECONDS_PER_DAY + 1),
                &server_secret_params(),
            )
            .expect_err("credential should not be valid 24h before redemption time");
        presentation
            .verify(
                DAY_ALIGNED_TIMESTAMP.add_seconds(2 * SECONDS_PER_DAY + 1),
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
            backup_id: libsignal_account_keys::BackupId(*b"a fake backup-id"),
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
            redemption_time: DAY_ALIGNED_TIMESTAMP.add_seconds(1),
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
            // Credential was for BackupLevel::Messages
            backup_level: BackupLevel::Paid,
            ..valid_presentation
        };
        invalid_presentation
            .verify(DAY_ALIGNED_TIMESTAMP, &server_secret_params())
            .expect_err("credential should not be valid with wrong receipt");
    }

    #[test]
    fn test_client_enforces_timestamp() {
        let redemption_time: Timestamp = DAY_ALIGNED_TIMESTAMP;

        let request_context = BackupAuthCredentialRequestContext::new(&KEY, ACI.into());
        let request = request_context.get_request();
        let blinded_credential = request.issue(
            redemption_time,
            BackupLevel::Free,
            BackupCredentialType::Messages,
            &server_secret_params(),
            ISSUE_RAND,
        );
        assert!(
            request_context
                .receive(
                    blinded_credential,
                    &server_secret_params().get_public_params(),
                    redemption_time.add_seconds(SECONDS_PER_DAY),
                )
                .is_err(),
            "client should require that timestamp matches its expectation"
        );
    }

    #[test]
    fn test_client_enforces_timestamp_granularity() {
        let redemption_time: Timestamp = DAY_ALIGNED_TIMESTAMP.add_seconds(60 * 60); // not on a day boundary!

        let request_context = BackupAuthCredentialRequestContext::new(&KEY, ACI.into());
        let request = request_context.get_request();
        let blinded_credential = request.issue(
            redemption_time,
            BackupLevel::Free,
            BackupCredentialType::Messages,
            &server_secret_params(),
            ISSUE_RAND,
        );
        assert!(
            request_context
                .receive(
                    blinded_credential,
                    &server_secret_params().get_public_params(),
                    redemption_time,
                )
                .is_err(),
            "client should require that timestamp is on a day boundary"
        );
    }

    #[test]
    fn test_backup_level_serialization() {
        let free_bytes = common::serialization::serialize(&BackupLevel::Free);
        let paid_bytes = common::serialization::serialize(&BackupLevel::Paid);
        assert_eq!(free_bytes.len(), 8);
        assert_eq!(paid_bytes.len(), 8);

        let free_num: u64 = common::serialization::deserialize(&free_bytes).expect("valid u64");
        let paid_num: u64 = common::serialization::deserialize(&paid_bytes).expect("valid u64");
        assert_eq!(free_num, 200);
        assert_eq!(paid_num, 201);

        let free: BackupLevel =
            common::serialization::deserialize(&free_bytes).expect("valid level");
        let paid: BackupLevel =
            common::serialization::deserialize(&paid_bytes).expect("valid level");
        assert_eq!(free, BackupLevel::Free);
        assert_eq!(paid, BackupLevel::Paid);
    }

    #[test]
    fn test_backup_level_validation() {
        // Check that the u64 level isn't just truncated to u8.
        assert_matches!(
            BackupLevel::try_from(0x100000000000u64 + u64::from(BackupLevel::Free)),
            Err(_)
        );
    }
}
