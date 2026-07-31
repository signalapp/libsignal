//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::{Aci, Pni};
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};
use zkcredential::credentials::{CredentialKeyPair, CredentialPublicKey};

use crate::api::auth::auth_credential_with_pni::AuthCredentialWithPniVersion;
use crate::common::constants::PRESENTATION_VERSION_4;
use crate::common::serialization::VersionByte;
use crate::common::simple_types::{RandomnessBytes, Timestamp};
use crate::crypto::uid_encryption;
use crate::crypto::uid_struct::UidStruct;
use crate::groups::{GroupPublicParams, GroupSecretParams, UuidCiphertext};
use crate::{ServerPublicParams, ServerSecretParams, ZkGroupVerificationFailure};

const CREDENTIAL_LABEL: &[u8] = b"20240222_Signal_AuthCredentialZkc";

/// Authentication credential implemented using [`zkcredential`].
///
/// The same credential as [`crate::api::auth::AuthCredentialWithPni`] but
/// implemented using the types and mechanism from the `zkcredential` crate.
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPniZkc {
    version: VersionByte<{ AuthCredentialWithPniVersion::Zkc as u8 }>,
    credential: zkcredential::credentials::Credential,
    aci: UidStruct,
    pni: UidStruct,
    redemption_time: Timestamp,
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPniZkcResponse {
    version: VersionByte<{ AuthCredentialWithPniVersion::Zkc as u8 }>,
    proof: zkcredential::issuance::IssuanceProof,
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPniZkcPresentation {
    version: VersionByte<PRESENTATION_VERSION_4>,
    proof: zkcredential::presentation::PresentationProof,
    aci_ciphertext: uid_encryption::Ciphertext,
    pni_ciphertext: uid_encryption::Ciphertext,
    redemption_time: Timestamp,
}

impl AuthCredentialWithPniZkcResponse {
    pub fn issue_credential(
        aci: Aci,
        pni: Pni,
        redemption_time: Timestamp,
        params: &ServerSecretParams,
        randomness: RandomnessBytes,
    ) -> Self {
        Self::issue_credential_for_key(
            aci,
            UidStruct::from_service_id(pni.into()),
            redemption_time,
            &params.generic_credential_key_pair,
            randomness,
        )
    }

    pub fn issue_credential_without_pni(
        aci: Aci,
        pni_salt: &[u8],
        redemption_time: Timestamp,
        params: &ServerSecretParams,
        randomness: RandomnessBytes,
    ) -> Self {
        Self::issue_credential_for_key(
            aci,
            UidStruct::for_false_pni_derived_from_aci(aci, pni_salt),
            redemption_time,
            &params.generic_credential_key_pair,
            randomness,
        )
    }

    pub fn receive(
        self,
        aci: Aci,
        pni: Pni,
        redemption_time: Timestamp,
        public_params: &ServerPublicParams,
    ) -> Result<AuthCredentialWithPniZkc, ZkGroupVerificationFailure> {
        self.receive_for_key(
            aci,
            UidStruct::from_service_id(pni.into()),
            redemption_time,
            &public_params.generic_credential_public_key,
        )
    }

    pub fn receive_without_pni(
        self,
        aci: Aci,
        pni_salt: &[u8],
        redemption_time: Timestamp,
        public_params: &ServerPublicParams,
    ) -> Result<AuthCredentialWithPniZkc, ZkGroupVerificationFailure> {
        self.receive_for_key(
            aci,
            UidStruct::for_false_pni_derived_from_aci(aci, pni_salt),
            redemption_time,
            &public_params.generic_credential_public_key,
        )
    }

    fn issue_credential_for_key(
        aci: Aci,
        pni_points: UidStruct,
        redemption_time: Timestamp,
        credential_key: &CredentialKeyPair,
        randomness: RandomnessBytes,
    ) -> Self {
        let proof = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&UidStruct::from_service_id(aci.into()))
            .add_attribute(&pni_points)
            .add_public_attribute(&redemption_time)
            .issue(credential_key, randomness);

        Self {
            version: VersionByte,
            proof,
        }
    }

    fn receive_for_key(
        self,
        aci: Aci,
        pni_points: UidStruct,
        redemption_time: Timestamp,
        public_key: &CredentialPublicKey,
    ) -> Result<AuthCredentialWithPniZkc, ZkGroupVerificationFailure> {
        if !redemption_time.is_day_aligned() {
            return Err(ZkGroupVerificationFailure);
        }

        let aci = UidStruct::from_service_id(aci.into());

        let raw_credential = zkcredential::issuance::IssuanceProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(&aci)
            .add_attribute(&pni_points)
            .add_public_attribute(&redemption_time)
            .verify(public_key, self.proof)?;

        Ok(AuthCredentialWithPniZkc {
            credential: raw_credential,
            version: VersionByte,
            aci,
            pni: pni_points,
            redemption_time,
        })
    }
}

impl AuthCredentialWithPniZkc {
    pub fn present(
        &self,
        public_params: &ServerPublicParams,
        group_secret_params: &GroupSecretParams,
        randomness: RandomnessBytes,
    ) -> AuthCredentialWithPniZkcPresentation {
        self.present_for_key(
            &public_params.generic_credential_public_key,
            group_secret_params,
            randomness,
        )
    }

    pub(crate) fn present_for_key(
        &self,
        public_key: &CredentialPublicKey,
        group_secret_params: &GroupSecretParams,
        randomness: RandomnessBytes,
    ) -> AuthCredentialWithPniZkcPresentation {
        let Self {
            aci,
            credential,
            pni,
            redemption_time,
            version: _,
        } = self;

        let proof = zkcredential::presentation::PresentationProofBuilder::new(CREDENTIAL_LABEL)
            .add_attribute(aci, &group_secret_params.uid_enc_key_pair)
            .add_attribute(pni, &group_secret_params.uid_enc_key_pair)
            .present(public_key, credential, randomness);

        AuthCredentialWithPniZkcPresentation {
            aci_ciphertext: group_secret_params.uid_enc_key_pair.encrypt(&self.aci),
            pni_ciphertext: group_secret_params.uid_enc_key_pair.encrypt(&self.pni),
            proof,
            redemption_time: *redemption_time,
            version: VersionByte,
        }
    }
}

impl AuthCredentialWithPniZkcPresentation {
    pub fn verify(
        &self,
        params: &ServerSecretParams,
        group_public_params: &GroupPublicParams,
        redemption_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        self.verify_for_key(
            &params.generic_credential_key_pair,
            group_public_params,
            redemption_time,
        )
    }

    pub(crate) fn verify_for_key(
        &self,
        credential_key: &CredentialKeyPair,
        group_public_params: &GroupPublicParams,
        redemption_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        zkcredential::presentation::PresentationProofVerifier::new(CREDENTIAL_LABEL)
            .add_attribute(
                &self.aci_ciphertext,
                &group_public_params.uid_enc_public_key,
            )
            .add_attribute(
                &self.pni_ciphertext,
                &group_public_params.uid_enc_public_key,
            )
            .add_public_attribute(&redemption_time)
            .verify(credential_key, &self.proof)
            .map_err(|_| ZkGroupVerificationFailure)
    }

    pub fn aci_ciphertext(&self) -> UuidCiphertext {
        UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.aci_ciphertext,
        }
    }

    pub fn pni_ciphertext(&self) -> UuidCiphertext {
        UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.pni_ciphertext,
        }
    }

    pub fn redemption_time(&self) -> Timestamp {
        self.redemption_time
    }
}

#[cfg(test)]
mod test {
    use zkcredential::RANDOMNESS_LEN;

    use super::*;
    use crate::SECONDS_PER_DAY;

    #[test]
    fn issue_receive_present() {
        const ACI: Aci = Aci::from_uuid_bytes([b'a'; 16]);
        const PNI: Pni = Pni::from_uuid_bytes([b'p'; 16]);
        const REDEMPTION_TIME: Timestamp = Timestamp::from_epoch_seconds(12345 * SECONDS_PER_DAY);

        let credential_key = CredentialKeyPair::generate([1; RANDOMNESS_LEN]);
        let public_key = credential_key.public_key();
        let group_secret_params = GroupSecretParams::generate([2; RANDOMNESS_LEN]);

        let response = AuthCredentialWithPniZkcResponse::issue_credential_for_key(
            ACI,
            UidStruct::from_service_id(PNI.into()),
            REDEMPTION_TIME,
            &credential_key,
            [3; RANDOMNESS_LEN],
        );

        let credential = response
            .clone()
            .receive_for_key(
                ACI,
                UidStruct::from_service_id(PNI.into()),
                REDEMPTION_TIME,
                public_key,
            )
            .expect("is valid");

        assert!(
            response
                .receive_for_key(
                    ACI,
                    UidStruct::for_false_pni_derived_from_aci(ACI, b"salt"),
                    REDEMPTION_TIME,
                    public_key,
                )
                .is_err(),
            "omitted PNI where one was expected"
        );

        let presentation =
            credential.present_for_key(public_key, &group_secret_params, [4; RANDOMNESS_LEN]);

        presentation
            .verify_for_key(
                &credential_key,
                &group_secret_params.get_public_params(),
                REDEMPTION_TIME,
            )
            .expect("can verify")
    }

    #[test]
    fn issue_receive_present_without_pni() {
        const ACI: Aci = Aci::from_uuid_bytes([b'a'; 16]);
        const REDEMPTION_TIME: Timestamp = Timestamp::from_epoch_seconds(12345 * SECONDS_PER_DAY);

        let credential_key = CredentialKeyPair::generate([1; RANDOMNESS_LEN]);
        let public_key = credential_key.public_key();
        let group_secret_params = GroupSecretParams::generate([2; RANDOMNESS_LEN]);

        let response = AuthCredentialWithPniZkcResponse::issue_credential_for_key(
            ACI,
            UidStruct::for_false_pni_derived_from_aci(ACI, b"salt"),
            REDEMPTION_TIME,
            &credential_key,
            [3; RANDOMNESS_LEN],
        );

        let credential = response
            .clone()
            .receive_for_key(
                ACI,
                UidStruct::for_false_pni_derived_from_aci(ACI, b"salt"),
                REDEMPTION_TIME,
                public_key,
            )
            .expect("is valid");

        assert!(
            response
                .clone()
                .receive_for_key(
                    ACI,
                    UidStruct::for_false_pni_derived_from_aci(ACI, b"pepper"),
                    REDEMPTION_TIME,
                    public_key,
                )
                .is_err(),
            "wrong salt"
        );
        assert!(
            response
                .receive_for_key(
                    ACI,
                    UidStruct::from_service_id(Pni::from_uuid_bytes([b'p'; 16]).into()),
                    REDEMPTION_TIME,
                    public_key,
                )
                .is_err(),
            "provided a PNI where one was not expected"
        );

        let presentation =
            credential.present_for_key(public_key, &group_secret_params, [4; RANDOMNESS_LEN]);

        presentation
            .verify_for_key(
                &credential_key,
                &group_secret_params.get_public_params(),
                REDEMPTION_TIME,
            )
            .expect("can verify");

        assert!(presentation.aci_ciphertext() != presentation.pni_ciphertext());
    }
}
