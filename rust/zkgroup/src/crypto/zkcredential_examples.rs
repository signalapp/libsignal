//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Examples of using zkcredential with existing zkgroup types.
//!
//! Has to live in zkgroup because they implement zkcredential traits on zkgroup types.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use poksho::{ShoApi, ShoSha256};
use serde::{Deserialize, Serialize};
use zkcredential::attributes::{self, Attribute, PublicKey, RevealedAttribute};
use zkcredential::credentials::CredentialKeyPair;
use zkcredential::issuance::blind::{
    BlindedAttribute, BlindedPoint, BlindingKeyPair, BlindingPublicKey, WithoutNonce,
};
use zkcredential::issuance::IssuanceProofBuilder;
use zkcredential::presentation::{
    PresentationProof, PresentationProofBuilder, PresentationProofVerifier,
};
use zkcredential::sho::ShoExt;

use crate::common::sho::*;
use crate::crypto::profile_key_struct::ProfileKeyStruct;
use crate::crypto::uid_struct::UidStruct;
use crate::crypto::{profile_key_encryption, uid_encryption};
use crate::{RANDOMNESS_LEN, TEST_ARRAY_16, TEST_ARRAY_32};

impl Attribute for ProfileKeyStruct {
    fn as_points(&self) -> [RistrettoPoint; 2] {
        [self.M3, self.M4]
    }
}

impl Attribute for profile_key_encryption::Ciphertext {
    fn as_points(&self) -> [RistrettoPoint; 2] {
        [self.E_B1, self.E_B2]
    }
}

const PROFILE_KEY_ENCRYPTION_ID: &str = "20220725-zkgroup-profilekey";

impl PublicKey for profile_key_encryption::PublicKey {
    fn A(&self) -> RistrettoPoint {
        self.B
    }

    fn G_a(&self) -> [RistrettoPoint; 2] {
        let system = profile_key_encryption::SystemParams::get_hardcoded();
        [system.G_b1, system.G_b2]
    }

    fn id(&self) -> &'static str {
        PROFILE_KEY_ENCRYPTION_ID
    }
}

impl PublicKey for profile_key_encryption::KeyPair {
    fn A(&self) -> RistrettoPoint {
        self.B
    }

    fn G_a(&self) -> [RistrettoPoint; 2] {
        let system = profile_key_encryption::SystemParams::get_hardcoded();
        [system.G_b1, system.G_b2]
    }

    fn id(&self) -> &'static str {
        PROFILE_KEY_ENCRYPTION_ID
    }
}

impl attributes::KeyPair for profile_key_encryption::KeyPair {
    fn a(&self) -> [Scalar; 2] {
        [self.b1, self.b2]
    }
}

#[test]
fn test_mac_generic() {
    let mut sho = ShoSha256::new(b"Test_Credentials");
    let keypair =
        CredentialKeyPair::generate(sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap());

    let label = b"20221221_AuthCredentialLike";

    let uid_bytes = TEST_ARRAY_16;
    let aci = libsignal_protocol::Aci::from_uuid_bytes(uid_bytes);
    let uid = UidStruct::from_service_id(aci.into());

    let proof = IssuanceProofBuilder::new(label)
        .add_attribute(&uid)
        .add_public_attribute(&[1, 2, 3])
        .issue(
            &keypair,
            sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap(),
        );

    let credential = IssuanceProofBuilder::new(label)
        .add_attribute(&uid)
        .add_public_attribute(&[1, 2, 3])
        .verify(keypair.public_key(), proof)
        .unwrap();

    let uid_encryption_key = uid_encryption::KeyPair::derive_from(&mut Sho::new(b"test", b""));
    let uid_encryption_public_key = uid_encryption_key.get_public_key();

    let proof = PresentationProofBuilder::new(label)
        .add_attribute(&uid, &uid_encryption_key)
        .present(
            keypair.public_key(),
            &credential,
            sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap(),
        );

    PresentationProofVerifier::new(label)
        .add_public_attribute(&[1, 2, 3])
        .add_attribute(&uid_encryption_key.encrypt(uid), &uid_encryption_public_key)
        .verify(&keypair, &proof)
        .unwrap()
}

#[test]
fn test_profile_key_credential() {
    let mut sho = ShoSha256::new(b"Test_Credentials");
    let keypair =
        CredentialKeyPair::generate(sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap());
    let blinding_keypair = BlindingKeyPair::generate(&mut sho);

    let label = b"20221221_ProfileKeyCredentialLike";

    let aci = libsignal_protocol::Aci::from_uuid_bytes(TEST_ARRAY_16);
    let uid = UidStruct::from_service_id(aci.into());
    let profile_key = ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
    let encrypted_profile_key = blinding_keypair.encrypt(&profile_key, &mut sho).into();

    #[derive(Serialize, Deserialize)]
    struct Request {
        uid: UidStruct,
        encrypted_profile_key: BlindedAttribute,
        blinding_public_key: BlindingPublicKey,
    }

    // Client
    let request_serialized = bincode::serialize(&Request {
        uid,
        encrypted_profile_key,
        blinding_public_key: *blinding_keypair.public_key(),
    })
    .unwrap();

    // Issuing server
    let request: Request = bincode::deserialize(&request_serialized).unwrap();

    let proof = IssuanceProofBuilder::with_authenticated_message(label, b"abc")
        .add_attribute(&request.uid)
        .add_blinded_attribute(&request.encrypted_profile_key)
        .issue(
            &keypair,
            &request.blinding_public_key,
            sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap(),
        );

    let proof_serialized = bincode::serialize(&proof).unwrap();

    // Client
    let credential = IssuanceProofBuilder::with_authenticated_message(label, b"abc")
        .add_attribute(&uid)
        .add_blinded_attribute(&encrypted_profile_key)
        .verify(
            keypair.public_key(),
            &blinding_keypair,
            bincode::deserialize(&proof_serialized).unwrap(),
        )
        .unwrap();

    let mut zkgroup_sho = Sho::new(b"test", b"");
    let uid_encryption_key = uid_encryption::KeyPair::derive_from(&mut zkgroup_sho);
    let profile_key_encryption_key = profile_key_encryption::KeyPair::derive_from(&mut zkgroup_sho);

    let proof = PresentationProofBuilder::with_authenticated_message(label, b"v1")
        .add_attribute(&uid, &uid_encryption_key)
        .add_attribute(&profile_key, &profile_key_encryption_key)
        .present(
            keypair.public_key(),
            &credential,
            sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap(),
        );

    #[derive(Serialize, Deserialize)]
    struct Presentation {
        proof: PresentationProof,
        encrypted_uid: uid_encryption::Ciphertext,
        encrypted_profile_key: profile_key_encryption::Ciphertext,
        uid_encryption_public_key: uid_encryption::PublicKey,
        profile_key_encryption_public_key: profile_key_encryption::PublicKey,
    }

    let presentation_serialized = bincode::serialize(&Presentation {
        proof,
        encrypted_uid: uid_encryption_key.encrypt(uid),
        encrypted_profile_key: profile_key_encryption_key.encrypt(profile_key),
        uid_encryption_public_key: uid_encryption_key.get_public_key(),
        profile_key_encryption_public_key: profile_key_encryption_key.get_public_key(),
    })
    .unwrap();

    // Verifying server
    let presentation: Presentation = bincode::deserialize(&presentation_serialized).unwrap();
    PresentationProofVerifier::with_authenticated_message(label, b"v1")
        .add_attribute(
            &presentation.encrypted_uid,
            &presentation.uid_encryption_public_key,
        )
        .add_attribute(
            &presentation.encrypted_profile_key,
            &presentation.profile_key_encryption_public_key,
        )
        .verify(&keypair, &presentation.proof)
        .unwrap();
}

#[test]
fn test_room_credential() {
    let mut sho = ShoSha256::new(b"RoomCredential");
    let keypair =
        CredentialKeyPair::generate(sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap());
    let blinding_keypair = BlindingKeyPair::generate(&mut sho);

    let label = b"20230330_RoomCredential";
    let request_label = b"20230330_RoomCredential_Request";

    #[derive(Serialize, Deserialize)]
    struct RoomId {
        opaque_id: RistrettoPoint,
    }
    impl RevealedAttribute for RoomId {
        fn as_point(&self) -> RistrettoPoint {
            self.opaque_id
        }
    }
    let room_id = RoomId {
        opaque_id: sho.get_point(),
    };
    let blinded_room_id = blinding_keypair.blind(&room_id, &mut sho);

    // Generate a request proof.
    let mut request_proof_statement = poksho::Statement::new();
    request_proof_statement.add("Y", &[("y", "G")]);
    request_proof_statement.add("D1", &[("r1", "G")]);
    // For most credentials we'd want to constraint D2 as well, but room IDs are unconstrained.
    // So we leave it out; if the client passes a wild D2, well, they won't get a credential back.
    let mut request_scalar_args = poksho::ScalarArgs::new();
    request_scalar_args.add("y", blinding_keypair.private_key().y);
    request_scalar_args.add("r1", blinded_room_id.r.0);
    let mut request_point_args = poksho::PointArgs::new();
    request_point_args.add("Y", blinding_keypair.public_key().Y);
    request_point_args.add("D1", blinded_room_id.D1);
    let proof = request_proof_statement
        .prove(
            &request_scalar_args,
            &request_point_args,
            request_label,
            &sho.squeeze_and_ratchet(RANDOMNESS_LEN)[..],
        )
        .expect("valid");

    let blinded_room_id: BlindedPoint<WithoutNonce> = blinded_room_id.into();

    #[derive(Serialize, Deserialize)]
    struct Request {
        blinded_room_id: BlindedPoint,
        blinding_public_key: BlindingPublicKey,
        proof: Vec<u8>,
    }

    // Client
    let request_serialized = bincode::serialize(&Request {
        blinded_room_id,
        blinding_public_key: *blinding_keypair.public_key(),
        proof,
    })
    .unwrap();

    // Issuing server
    let request: Request = bincode::deserialize(&request_serialized).unwrap();

    let mut request_verifying_point_args = poksho::PointArgs::new();
    request_verifying_point_args.add("Y", request.blinding_public_key.Y);
    request_verifying_point_args.add("D1", request.blinded_room_id.D1);
    request_proof_statement
        .verify_proof(&request.proof, &request_verifying_point_args, request_label)
        .expect("valid");

    let expiration = 1680220000u32;

    let proof = IssuanceProofBuilder::new(label)
        .add_public_attribute(&expiration)
        .add_blinded_revealed_attribute(&request.blinded_room_id)
        .issue(
            &keypair,
            &request.blinding_public_key,
            sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap(),
        );

    let proof_serialized = bincode::serialize(&proof).unwrap();

    // Client
    let credential = IssuanceProofBuilder::new(label)
        .add_public_attribute(&expiration)
        .add_blinded_revealed_attribute(&blinded_room_id)
        .verify(
            keypair.public_key(),
            &blinding_keypair,
            bincode::deserialize(&proof_serialized).unwrap(),
        )
        .unwrap();

    let proof = PresentationProofBuilder::new(label)
        .add_revealed_attribute(&room_id)
        .present(
            keypair.public_key(),
            &credential,
            sho.squeeze_and_ratchet(RANDOMNESS_LEN).try_into().unwrap(),
        );

    #[derive(Serialize, Deserialize)]
    struct Presentation {
        proof: PresentationProof,
        room_id: RoomId,
        expiration: u32,
    }

    let presentation_serialized = bincode::serialize(&Presentation {
        proof,
        room_id,
        expiration,
    })
    .unwrap();

    // Verifying server
    let presentation: Presentation = bincode::deserialize(&presentation_serialized).unwrap();
    PresentationProofVerifier::new(label)
        .add_public_attribute(&presentation.expiration)
        .add_revealed_attribute(&presentation.room_id)
        .verify(&keypair, &presentation.proof)
        .unwrap();
}
