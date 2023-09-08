//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(non_snake_case)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;

use serde::{Deserialize, Serialize};

use crate::common::array_utils::OneBased;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::sho::*;
use crate::common::simple_types::*;
use crate::crypto::receipt_struct::ReceiptStruct;
use crate::crypto::timestamp_struct::TimestampStruct;
use crate::crypto::{
    credentials, profile_key_commitment, profile_key_credential_request, profile_key_encryption,
    profile_key_struct, receipt_credential_request, uid_encryption, uid_struct,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialWithPniIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileKeyCredentialRequestProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExpiringProfileKeyCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ReceiptCredentialIssuanceProof {
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialPresentationProofV2 {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_V: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthCredentialWithPniPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_y5: RistrettoPoint,
    C_V: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

/// Deprecated; use [ExpiringProfileKeyCredentialPresentationProof] instead.
///
/// Kept around so that v1 ProfileKeyCredentialPresentations can still be deserialized,
/// even though they can't be verified.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileKeyCredentialPresentationProofV1 {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_V: RistrettoPoint,
    C_z: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

/// Deprecated; use [ExpiringProfileKeyCredentialPresentationProof] instead.
///
/// Kept around so that v2 ProfileKeyCredentialPresentations can still be deserialized,
/// even though they can't be verified.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileKeyCredentialPresentationProofV2 {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_V: RistrettoPoint,
    C_z: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExpiringProfileKeyCredentialPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_y3: RistrettoPoint,
    C_y4: RistrettoPoint,
    C_y5: RistrettoPoint,
    C_V: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ReceiptCredentialPresentationProof {
    C_x0: RistrettoPoint,
    C_x1: RistrettoPoint,
    C_y1: RistrettoPoint,
    C_y2: RistrettoPoint,
    C_V: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

impl AuthCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);
        st.add(
            "G_V-I",
            &[
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
                ("y3", "G_y3"),
            ],
        );
        st.add(
            "V",
            &[
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
                ("y2", "M2"),
                ("y3", "M3"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::AuthCredential>,
        credential: credentials::AuthCredential,
        uid: uid_struct::UidStruct,
        redemption_time: CoarseRedemptionTime,
        sho: &mut Sho,
    ) -> Self {
        let system = credentials::SystemParams::get_hardcoded();

        let M = credentials::convert_to_points_uid_struct(uid, redemption_time);

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y[1]);
        scalar_args.add("y2", key_pair.y[2]);
        scalar_args.add("y3", key_pair.y[3]);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key_pair.C_W);
        point_args.add("G_w", system.G_w);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_V-I", system.G_V - key_pair.I);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_y[1]);
        point_args.add("G_y2", system.G_y[2]);
        point_args.add("G_y3", system.G_y[3]);
        point_args.add("V", credential.V);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("M1", M[0]);
        point_args.add("M2", M[1]);
        point_args.add("M3", M[2]);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        Self { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: credentials::PublicKey,
        credential: credentials::AuthCredential,
        uid_struct: uid_struct::UidStruct,
        redemption_time: CoarseRedemptionTime,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let system = credentials::SystemParams::get_hardcoded();

        let M = credentials::convert_to_points_uid_struct(uid_struct, redemption_time);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", public_key.C_W);
        point_args.add("G_w", system.G_w);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_V-I", system.G_V - public_key.I);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_y[1]);
        point_args.add("G_y2", system.G_y[2]);
        point_args.add("G_y3", system.G_y[3]);
        point_args.add("V", credential.V);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("M1", M[0]);
        point_args.add("M2", M[1]);
        point_args.add("M3", M[2]);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl AuthCredentialWithPniIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);
        st.add(
            "G_V-I",
            &[
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
                ("y3", "G_y3"),
                ("y4", "G_y4"),
                ("y5", "G_y5"),
            ],
        );
        st.add(
            "V",
            &[
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
                ("y2", "M2"),
                ("y3", "M3"),
                ("y4", "M4"),
                ("y5", "M5"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::AuthCredentialWithPni>,
        credential: credentials::AuthCredentialWithPni,
        aci: uid_struct::UidStruct,
        pni: uid_struct::UidStruct,
        redemption_time: Timestamp,
        sho: &mut Sho,
    ) -> Self {
        let system = credentials::SystemParams::get_hardcoded();

        let M = OneBased(credentials::convert_to_points_aci_pni_timestamp(
            aci,
            pni,
            redemption_time,
        ));

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y[1]);
        scalar_args.add("y2", key_pair.y[2]);
        scalar_args.add("y3", key_pair.y[3]);
        scalar_args.add("y4", key_pair.y[4]);
        scalar_args.add("y5", key_pair.y[5]);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key_pair.C_W);
        point_args.add("G_w", system.G_w);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_V-I", system.G_V - key_pair.I);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_y[1]);
        point_args.add("G_y2", system.G_y[2]);
        point_args.add("G_y3", system.G_y[3]);
        point_args.add("G_y4", system.G_y[4]);
        point_args.add("G_y5", system.G_y[5]);
        point_args.add("V", credential.V);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("M1", M[1]);
        point_args.add("M2", M[2]);
        point_args.add("M3", M[3]);
        point_args.add("M4", M[4]);
        point_args.add("M5", M[5]);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        Self { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: credentials::PublicKey,
        credential: credentials::AuthCredentialWithPni,
        aci_struct: uid_struct::UidStruct,
        pni_struct: uid_struct::UidStruct,
        redemption_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let system = credentials::SystemParams::get_hardcoded();

        let M = OneBased(credentials::convert_to_points_aci_pni_timestamp(
            aci_struct,
            pni_struct,
            redemption_time,
        ));

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", public_key.C_W);
        point_args.add("G_w", system.G_w);
        point_args.add("G_wprime", system.G_wprime);
        point_args.add("G_V-I", system.G_V - public_key.I);
        point_args.add("G_x0", system.G_x0);
        point_args.add("G_x1", system.G_x1);
        point_args.add("G_y1", system.G_y[1]);
        point_args.add("G_y2", system.G_y[2]);
        point_args.add("G_y3", system.G_y[3]);
        point_args.add("G_y4", system.G_y[4]);
        point_args.add("G_y5", system.G_y[5]);
        point_args.add("V", credential.V);
        point_args.add("U", credential.U);
        point_args.add("tU", credential.t * credential.U);
        point_args.add("M1", M[1]);
        point_args.add("M2", M[2]);
        point_args.add("M3", M[3]);
        point_args.add("M4", M[4]);
        point_args.add("M5", M[5]);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ProfileKeyCredentialRequestProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("Y", &[("y", "G")]);
        st.add("D1", &[("r1", "G")]);
        st.add("E1", &[("r2", "G")]);
        st.add("J3", &[("j3", "G_j3")]);
        st.add("D2-J1", &[("r1", "Y"), ("j3", "-G_j1")]);
        st.add("E2-J2", &[("r2", "Y"), ("j3", "-G_j2")]);
        st
    }

    pub fn new(
        key_pair: profile_key_credential_request::KeyPair,
        ciphertext: profile_key_credential_request::CiphertextWithSecretNonce,
        commitment: profile_key_commitment::CommitmentWithSecretNonce,
        sho: &mut Sho,
    ) -> ProfileKeyCredentialRequestProof {
        let commitment_system = profile_key_commitment::SystemParams::get_hardcoded();

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("y", key_pair.y);
        scalar_args.add("r1", ciphertext.r1);
        scalar_args.add("r2", ciphertext.r2);
        scalar_args.add("j3", commitment.j3);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", key_pair.Y);
        point_args.add("D1", ciphertext.D1);
        point_args.add("E1", ciphertext.E1);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("D2-J1", ciphertext.D2 - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("E2-J2", ciphertext.E2 - commitment.J2);
        point_args.add("-G_j2", -commitment_system.G_j2);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        ProfileKeyCredentialRequestProof { poksho_proof }
    }

    pub fn verify(
        &self,
        public_key: profile_key_credential_request::PublicKey,
        ciphertext: profile_key_credential_request::Ciphertext,
        commitment: profile_key_commitment::Commitment,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let commitment_system = profile_key_commitment::SystemParams::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();
        point_args.add("Y", public_key.Y);
        point_args.add("D1", ciphertext.D1);
        point_args.add("E1", ciphertext.E1);
        point_args.add("J3", commitment.J3);
        point_args.add("G_j3", commitment_system.G_j3);
        point_args.add("D2-J1", ciphertext.D2 - commitment.J1);
        point_args.add("-G_j1", -commitment_system.G_j1);
        point_args.add("E2-J2", ciphertext.E2 - commitment.J2);
        point_args.add("-G_j2", -commitment_system.G_j2);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ExpiringProfileKeyCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);
        st.add(
            "G_V-I",
            &[
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
                ("y3", "G_y3"),
                ("y4", "G_y4"),
                ("y5", "G_y5"),
            ],
        );
        st.add("S1", &[("y3", "D1"), ("y4", "E1"), ("rprime", "G")]);
        st.add(
            "S2",
            &[
                ("y3", "D2"),
                ("y4", "E2"),
                ("rprime", "Y"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
                ("y2", "M2"),
                ("y5", "M5"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::ExpiringProfileKeyCredential>,
        request_public_key: profile_key_credential_request::PublicKey,
        request: profile_key_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedExpiringProfileKeyCredentialWithSecretNonce,
        uid: uid_struct::UidStruct,
        credential_expiration_time: Timestamp,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let m5 = TimestampStruct::calc_m_from(credential_expiration_time);
        let M5 = m5 * credentials_system.G_m5;

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y[1]);
        scalar_args.add("y2", key_pair.y[2]);
        scalar_args.add("y3", key_pair.y[3]);
        scalar_args.add("y4", key_pair.y[4]);
        scalar_args.add("y5", key_pair.y[5]);
        scalar_args.add("rprime", blinded_credential.rprime);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key_pair.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - key_pair.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("G_y5", credentials_system.G_y[5]);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", uid.M1);
        point_args.add("M2", uid.M2);
        point_args.add("M5", M5);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        ExpiringProfileKeyCredentialIssuanceProof { poksho_proof }
    }

    pub fn verify(
        &self,
        credentials_public_key: credentials::PublicKey,
        request_public_key: profile_key_credential_request::PublicKey,
        aci_bytes: UidBytes,
        request: profile_key_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedExpiringProfileKeyCredential,
        credential_expiration_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let aci = libsignal_protocol::Aci::from_uuid_bytes(aci_bytes);
        let uid = uid_struct::UidStruct::from_service_id(aci.into());

        let m5 = TimestampStruct::calc_m_from(credential_expiration_time);
        let M5 = m5 * credentials_system.G_m5;

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", credentials_public_key.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - credentials_public_key.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("G_y5", credentials_system.G_y[5]);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("E1", request.E1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("E2", request.E2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", uid.M1);
        point_args.add("M2", uid.M2);
        point_args.add("M5", M5);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ReceiptCredentialIssuanceProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("C_W", &[("w", "G_w"), ("wprime", "G_wprime")]);
        st.add(
            "G_V-I",
            &[
                ("x0", "G_x0"),
                ("x1", "G_x1"),
                ("y1", "G_y1"),
                ("y2", "G_y2"),
            ],
        );
        st.add("S1", &[("y2", "D1"), ("rprime", "G")]);
        st.add(
            "S2",
            &[
                ("y2", "D2"),
                ("rprime", "Y"),
                ("w", "G_w"),
                ("x0", "U"),
                ("x1", "tU"),
                ("y1", "M1"),
            ],
        );
        st
    }

    pub fn new(
        key_pair: credentials::KeyPair<credentials::ReceiptCredential>,
        request_public_key: receipt_credential_request::PublicKey,
        request: receipt_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedReceiptCredentialWithSecretNonce,
        receipt_expiration_time: Timestamp,
        receipt_level: ReceiptLevel,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let m1 = ReceiptStruct::calc_m1_from(receipt_expiration_time, receipt_level);

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("w", key_pair.w);
        scalar_args.add("wprime", key_pair.wprime);
        scalar_args.add("x0", key_pair.x0);
        scalar_args.add("x1", key_pair.x1);
        scalar_args.add("y1", key_pair.y[1]);
        scalar_args.add("y2", key_pair.y[2]);
        scalar_args.add("rprime", blinded_credential.rprime);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", key_pair.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - key_pair.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", m1 * credentials_system.G_m1);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();
        Self { poksho_proof }
    }

    pub fn verify(
        &self,
        credentials_public_key: credentials::PublicKey,
        request_public_key: receipt_credential_request::PublicKey,
        request: receipt_credential_request::Ciphertext,
        blinded_credential: credentials::BlindedReceiptCredential,
        receipt_struct: ReceiptStruct,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let M = credentials::convert_to_points_receipt_struct(receipt_struct);

        let mut point_args = poksho::PointArgs::new();
        point_args.add("C_W", credentials_public_key.C_W);
        point_args.add("G_w", credentials_system.G_w);
        point_args.add("G_wprime", credentials_system.G_wprime);
        point_args.add("G_V-I", credentials_system.G_V - credentials_public_key.I);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("S1", blinded_credential.S1);
        point_args.add("D1", request.D1);
        point_args.add("S2", blinded_credential.S2);
        point_args.add("D2", request.D2);
        point_args.add("Y", request_public_key.Y);
        point_args.add("U", blinded_credential.U);
        point_args.add("tU", blinded_credential.t * blinded_credential.U);
        point_args.add("M1", M[0]);

        match Self::get_poksho_statement().verify_proof(&self.poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl AuthCredentialPresentationProofV2 {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a1", "G_a1"), ("a2", "G_a2")]);
        st.add("C_y2-E_A2", &[("z", "G_y2"), ("a2", "-E_A1")]);
        st.add("C_y3", &[("z", "G_y3")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        uid_enc_key_pair: uid_encryption::KeyPair,
        credential: credentials::AuthCredential,
        uid: uid_struct::UidStruct,
        uid_ciphertext: uid_encryption::Ciphertext,
        redemption_time: CoarseRedemptionTime,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid_system = uid_encryption::SystemParams::get_hardcoded();
        let M = credentials::convert_to_points_uid_struct(uid, redemption_time);

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1] + M[0];
        let C_y2 = z * credentials_system.G_y[2] + M[1];
        let C_y3 = z * credentials_system.G_y[3];

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;

        let z0 = -z * credential.t;
        //let z1 = -z * uid_enc_key_pair.a1;

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("a2", uid_enc_key_pair.a2);
        //scalar_args.add("z1", z1);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("G_a2", uid_system.G_a2);
        point_args.add("C_y2-E_A2", C_y2 - uid_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_V,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair<credentials::AuthCredential>,
        uid_enc_public_key: uid_encryption::PublicKey,
        uid_ciphertext: uid_encryption::Ciphertext,
        redemption_time: CoarseRedemptionTime,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let enc_system = uid_encryption::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_V,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_V) = (*C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_V);

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y: OneBased([y1, y2, y3, ..]),
            I,
            ..
        } = credentials_key_pair;

        let m3 = encode_redemption_time(redemption_time);
        let M3 = m3 * credentials_system.G_m3;
        let Z = C_V - W - x0 * C_x0 - x1 * C_x1 - y1 * C_y1 - y2 * C_y2 - y3 * (C_y3 + M3);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a1", enc_system.G_a1);
        point_args.add("G_a2", enc_system.G_a2);
        point_args.add("C_y2-E_A2", C_y2 - uid_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        //point_args.add("E_A1", uid_ciphertext.E_A1);
        //point_args.add("C_y1", C_y1);
        //point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);
        //point_args.add("0", RistrettoPoint::identity());

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl AuthCredentialWithPniPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add("A", &[("a1", "G_a1"), ("a2", "G_a2")]);
        st.add("C_y2-E_A2", &[("z", "G_y2"), ("a2", "-E_A1")]);
        st.add("E_A1", &[("a1", "C_y1"), ("z1", "G_y1")]);
        st.add("C_y4-E_B2", &[("z", "G_y4"), ("a2", "-E_B1")]);
        st.add("E_B1", &[("a1", "C_y3"), ("z1", "G_y3")]);
        st.add("0", &[("z1", "I"), ("a1", "Z")]);
        st
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credentials_public_key: credentials::PublicKey,
        uid_enc_key_pair: uid_encryption::KeyPair,
        credential: credentials::AuthCredentialWithPni,
        aci: uid_struct::UidStruct,
        aci_ciphertext: uid_encryption::Ciphertext,
        pni: uid_struct::UidStruct,
        pni_ciphertext: uid_encryption::Ciphertext,
        redemption_time: Timestamp,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid_system = uid_encryption::SystemParams::get_hardcoded();
        let M = OneBased(credentials::convert_to_points_aci_pni_timestamp(
            aci,
            pni,
            redemption_time,
        ));

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1] + M[1];
        let C_y2 = z * credentials_system.G_y[2] + M[2];
        let C_y3 = z * credentials_system.G_y[3] + M[3];
        let C_y4 = z * credentials_system.G_y[4] + M[4];
        let C_y5 = z * credentials_system.G_y[5];

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;

        let z0 = -z * credential.t;
        let z1 = -z * uid_enc_key_pair.a1;

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("a2", uid_enc_key_pair.a2);
        scalar_args.add("z1", z1);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);

        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);

        point_args.add("A", uid_enc_key_pair.A);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("G_a2", uid_system.G_a2);

        point_args.add("C_y2-E_A2", C_y2 - aci_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -aci_ciphertext.E_A1);
        point_args.add("E_A1", aci_ciphertext.E_A1);
        point_args.add("C_y1", C_y1);
        point_args.add("G_y1", credentials_system.G_y[1]);

        point_args.add("C_y4-E_B2", C_y4 - pni_ciphertext.E_A2);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("-E_B1", -pni_ciphertext.E_A1);
        point_args.add("E_B1", pni_ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("0", RistrettoPoint::identity());

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_V,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair<credentials::AuthCredentialWithPni>,
        uid_enc_public_key: uid_encryption::PublicKey,
        aci_ciphertext: uid_encryption::Ciphertext,
        pni_ciphertext: uid_encryption::Ciphertext,
        redemption_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let uid_enc_system = uid_encryption::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_V,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_y5, C_V) =
            (*C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_y4, *C_y5, *C_V);

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y: OneBased([y1, y2, y3, y4, y5]),
            I,
            ..
        } = credentials_key_pair;

        let m5 = TimestampStruct::calc_m_from(redemption_time);
        let M5 = m5 * credentials_system.G_m5;
        let Z = C_V
            - W
            - x0 * C_x0
            - x1 * C_x1
            - y1 * C_y1
            - y2 * C_y2
            - y3 * C_y3
            - y4 * C_y4
            - y5 * (C_y5 + M5);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);

        point_args.add("A", uid_enc_public_key.A);
        point_args.add("G_a1", uid_enc_system.G_a1);
        point_args.add("G_a2", uid_enc_system.G_a2);

        point_args.add("C_y2-E_A2", C_y2 - aci_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -aci_ciphertext.E_A1);
        point_args.add("E_A1", aci_ciphertext.E_A1);
        point_args.add("C_y1", C_y1);
        point_args.add("G_y1", credentials_system.G_y[1]);

        point_args.add("C_y4-E_B2", C_y4 - pni_ciphertext.E_A2);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("-E_B1", -pni_ciphertext.E_A1);
        point_args.add("E_B1", pni_ciphertext.E_A1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("0", RistrettoPoint::identity());

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ProfileKeyCredentialPresentationProofV1 {
    pub(crate) fn from_invalid_proof(poksho_proof: Vec<u8>) -> Self {
        Self {
            C_x0: RISTRETTO_BASEPOINT_POINT,
            C_x1: RISTRETTO_BASEPOINT_POINT,
            C_y1: RISTRETTO_BASEPOINT_POINT,
            C_y2: RISTRETTO_BASEPOINT_POINT,
            C_y3: RISTRETTO_BASEPOINT_POINT,
            C_y4: RISTRETTO_BASEPOINT_POINT,
            C_V: RISTRETTO_BASEPOINT_POINT,
            C_z: RISTRETTO_BASEPOINT_POINT,
            poksho_proof,
        }
    }
}

impl ExpiringProfileKeyCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();
        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1")]);
        st.add(
            "A+B",
            &[
                ("a1", "G_a1"),
                ("a2", "G_a2"),
                ("b1", "G_b1"),
                ("b2", "G_b2"),
            ],
        );
        st.add("C_y2-E_A2", &[("z", "G_y2"), ("a2", "-E_A1")]);
        st.add("E_A1", &[("a1", "C_y1"), ("z1", "G_y1")]);
        st.add("C_y4-E_B2", &[("z", "G_y4"), ("b2", "-E_B1")]);
        st.add("E_B1", &[("b1", "C_y3"), ("z2", "G_y3")]);
        st.add("0", &[("z1", "I"), ("a1", "Z")]);
        st.add("0", &[("z2", "I"), ("b1", "Z")]);
        st
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uid_enc_key_pair: uid_encryption::KeyPair,
        profile_key_enc_key_pair: profile_key_encryption::KeyPair,
        credentials_public_key: credentials::PublicKey,
        credential: credentials::ExpiringProfileKeyCredential,
        uid_ciphertext: uid_encryption::Ciphertext,
        profile_key_ciphertext: profile_key_encryption::Ciphertext,
        aci_bytes: UidBytes,
        profile_key_bytes: ProfileKeyBytes,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let uid_system = uid_encryption::SystemParams::get_hardcoded();
        let profile_key_system = profile_key_encryption::SystemParams::get_hardcoded();
        let aci = libsignal_protocol::Aci::from_uuid_bytes(aci_bytes);
        let uid = uid_struct::UidStruct::from_service_id(aci.into());
        let profile_key = profile_key_struct::ProfileKeyStruct::new(profile_key_bytes, aci_bytes);

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1] + uid.M1;
        let C_y2 = z * credentials_system.G_y[2] + uid.M2;
        let C_y3 = z * credentials_system.G_y[3] + profile_key.M3;
        let C_y4 = z * credentials_system.G_y[4] + profile_key.M4;
        let C_y5 = z * credentials_system.G_y[5];

        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_V = z * credentials_system.G_V + credential.V;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;

        let z0 = -z * credential.t;
        let z1 = -z * uid_enc_key_pair.a1;
        let z2 = -z * profile_key_enc_key_pair.b1;

        let I = credentials_public_key.I;
        let Z = z * I;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("z0", z0);
        scalar_args.add("a1", uid_enc_key_pair.a1);
        scalar_args.add("a2", uid_enc_key_pair.a2);
        scalar_args.add("b1", profile_key_enc_key_pair.b1);
        scalar_args.add("b2", profile_key_enc_key_pair.b2);
        scalar_args.add("z1", z1);
        scalar_args.add("z2", z2);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);

        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);

        point_args.add("A+B", uid_enc_key_pair.A + profile_key_enc_key_pair.B);
        point_args.add("G_a1", uid_system.G_a1);
        point_args.add("G_a2", uid_system.G_a2);
        point_args.add("G_b1", profile_key_system.G_b1);
        point_args.add("G_b2", profile_key_system.G_b2);

        point_args.add("C_y2-E_A2", C_y2 - uid_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("C_y1", C_y1);
        point_args.add("G_y1", credentials_system.G_y[1]);

        point_args.add("C_y4-E_B2", C_y4 - profile_key_ciphertext.E_B2);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("-E_B1", -profile_key_ciphertext.E_B1);
        point_args.add("E_B1", profile_key_ciphertext.E_B1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("0", RistrettoPoint::identity());

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        ExpiringProfileKeyCredentialPresentationProof {
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_x0,
            C_x1,
            C_V,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair<credentials::ExpiringProfileKeyCredential>,
        uid_ciphertext: uid_encryption::Ciphertext,
        uid_enc_public_key: uid_encryption::PublicKey,
        profile_key_ciphertext: profile_key_encryption::Ciphertext,
        profile_key_enc_public_key: profile_key_encryption::PublicKey,
        credential_expiration_time: Timestamp,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let uid_enc_system = uid_encryption::SystemParams::get_hardcoded();
        let profile_key_enc_system = profile_key_encryption::SystemParams::get_hardcoded();
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_y3,
            C_y4,
            C_y5,
            C_V,
            poksho_proof,
        } = self;

        let (C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_V) =
            (*C_x0, *C_x1, *C_y1, *C_y2, *C_y3, *C_y4, *C_V);

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y: OneBased([y1, y2, y3, y4, y5]),
            I,
            ..
        } = credentials_key_pair;

        let m5 = TimestampStruct::calc_m_from(credential_expiration_time);
        let M5 = m5 * credentials_system.G_m5;

        let Z = C_V
            - W
            - x0 * C_x0
            - x1 * C_x1
            - (y1 * C_y1)
            - (y2 * C_y2)
            - (y3 * C_y3)
            - (y4 * C_y4)
            - (y5 * (C_y5 + M5));

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x1", C_x1);
        point_args.add("C_x0", C_x0);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);

        point_args.add("A+B", uid_enc_public_key.A + profile_key_enc_public_key.B);
        point_args.add("G_a1", uid_enc_system.G_a1);
        point_args.add("G_a2", uid_enc_system.G_a2);
        point_args.add("G_b1", profile_key_enc_system.G_b1);
        point_args.add("G_b2", profile_key_enc_system.G_b2);

        point_args.add("C_y2-E_A2", C_y2 - uid_ciphertext.E_A2);
        point_args.add("G_y2", credentials_system.G_y[2]);
        point_args.add("-E_A1", -uid_ciphertext.E_A1);
        point_args.add("E_A1", uid_ciphertext.E_A1);
        point_args.add("C_y1", C_y1);
        point_args.add("G_y1", credentials_system.G_y[1]);

        point_args.add("C_y4-E_B2", C_y4 - profile_key_ciphertext.E_B2);
        point_args.add("G_y4", credentials_system.G_y[4]);
        point_args.add("-E_B1", -profile_key_ciphertext.E_B1);
        point_args.add("E_B1", profile_key_ciphertext.E_B1);
        point_args.add("C_y3", C_y3);
        point_args.add("G_y3", credentials_system.G_y[3]);
        point_args.add("0", RistrettoPoint::identity());

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}

impl ReceiptCredentialPresentationProof {
    pub fn get_poksho_statement() -> poksho::Statement {
        let mut st = poksho::Statement::new();

        st.add("Z", &[("z", "I")]);
        st.add("C_x1", &[("t", "C_x0"), ("-zt", "G_x0"), ("z", "G_x1")]);
        st.add("C_y1", &[("z", "G_y1")]);
        st.add("C_y2", &[("z", "G_y2")]);
        st
    }

    pub fn new(
        credentials_public_key: credentials::PublicKey,
        credential: credentials::ReceiptCredential,
        sho: &mut Sho,
    ) -> Self {
        let credentials_system = credentials::SystemParams::get_hardcoded();

        let z = sho.get_scalar();

        let C_y1 = z * credentials_system.G_y[1];
        let C_y2 = z * credentials_system.G_y[2];

        let I = credentials_public_key.I;
        let Z = z * I;
        let C_x0 = z * credentials_system.G_x0 + credential.U;
        let C_x1 = z * credentials_system.G_x1 + credential.t * credential.U;
        let C_V = z * credentials_system.G_V + credential.V;

        // Scalars listed in order of stmts for debugging
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("t", credential.t);
        scalar_args.add("-zt", -z * credential.t);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x0", C_x0);
        point_args.add("C_x1", C_x1);
        point_args.add("C_y1", C_y1);
        point_args.add("C_y2", C_y2);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);

        let poksho_proof = Self::get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                &[],
                &sho.squeeze(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_V,
            poksho_proof,
        }
    }

    pub fn verify(
        &self,
        credentials_key_pair: credentials::KeyPair<credentials::ReceiptCredential>,
        receipt_struct: ReceiptStruct,
    ) -> Result<(), ZkGroupVerificationFailure> {
        let credentials_system = credentials::SystemParams::get_hardcoded();
        let M = credentials::convert_to_points_receipt_struct(receipt_struct);

        let Self {
            C_x0,
            C_x1,
            C_y1,
            C_y2,
            C_V,
            poksho_proof,
        } = self;
        let (C_x0, C_x1, C_y1, C_y2, C_V) = (*C_x0, *C_x1, *C_y1, *C_y2, *C_V);

        let credentials::KeyPair {
            W,
            x0,
            x1,
            y: OneBased([y1, y2, ..]),
            I,
            ..
        } = credentials_key_pair;

        let Z = C_V - W - x0 * C_x0 - x1 * C_x1 - y1 * (C_y1 + M[0]) - y2 * (C_y2 + M[1]);

        // Points listed in order of stmts for debugging
        let mut point_args = poksho::PointArgs::new();
        point_args.add("Z", Z);
        point_args.add("I", I);
        point_args.add("C_x0", C_x0);
        point_args.add("C_x1", C_x1);
        point_args.add("C_y1", C_y1);
        point_args.add("C_y2", C_y2);
        point_args.add("G_x0", credentials_system.G_x0);
        point_args.add("G_x1", credentials_system.G_x1);
        point_args.add("G_y1", credentials_system.G_y[1]);
        point_args.add("G_y2", credentials_system.G_y[2]);

        match Self::get_poksho_statement().verify_proof(poksho_proof, &point_args, &[]) {
            Err(_) => Err(ZkGroupVerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}
