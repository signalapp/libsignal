//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::groups::GroupSendCredentialResponse;
use zkgroup::{RandomnessBytes, Timestamp, RANDOMNESS_LEN, SECONDS_PER_DAY, UUID_LEN};

const DAY_ALIGNED_TIMESTAMP: Timestamp = 1681344000; // 2023-04-13 00:00:00 UTC

#[test]
fn test_credential() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];
    let randomness4: RandomnessBytes = [0x46u8; RANDOMNESS_LEN];

    // first set up a group
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);

    let moxie_user_id =
        libsignal_core::Aci::from(uuid::uuid!("e36fdce7-36da-4c6f-a21b-9afe2b754650"));
    let brian_user_id =
        libsignal_core::Aci::from(uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d"));

    let group_members = [
        client_user_id.into(),
        moxie_user_id.into(),
        brian_user_id.into(),
    ];
    let group_members_without_requester = [brian_user_id.into(), moxie_user_id.into()];

    let group_secret_params = zkgroup::groups::GroupSecretParams::generate(randomness1);
    let ciphertexts: Vec<_> = group_members
        .iter()
        .map(|member| group_secret_params.encrypt_service_id(*member))
        .collect();
    let client_user_id_ciphertext = group_secret_params.encrypt_service_id(client_user_id.into());

    // server generated materials; issuance request -> issuance response
    let server_secret_params = zkgroup::ServerSecretParams::generate(randomness2);
    let credential_response = GroupSendCredentialResponse::issue_credential(
        ciphertexts.iter().copied(),
        &client_user_id_ciphertext,
        DAY_ALIGNED_TIMESTAMP,
        &server_secret_params,
        randomness3,
    )
    .expect("valid request");

    // client generated materials; issuance response -> redemption request
    let server_public_params = server_secret_params.get_public_params();
    let credential = credential_response
        .receive(
            &server_public_params,
            &group_secret_params,
            group_members,
            client_user_id.into(),
            DAY_ALIGNED_TIMESTAMP,
        )
        .expect("issued credential should be valid");

    let presentation = credential.present(&server_public_params, randomness4);

    // server verification of the credential presentation
    presentation
        .verify(
            group_members_without_requester,
            DAY_ALIGNED_TIMESTAMP,
            &server_secret_params,
        )
        .expect("credential should be valid for the timestamp given");

    // Try again with the alternate receive implementation
    let credential_response = GroupSendCredentialResponse::issue_credential(
        ciphertexts.iter().copied(),
        &client_user_id_ciphertext,
        DAY_ALIGNED_TIMESTAMP,
        &server_secret_params,
        randomness3,
    )
    .expect("valid request");

    let credential = credential_response
        .receive_with_ciphertexts(
            &server_public_params,
            &group_secret_params,
            ciphertexts.iter().copied(),
            &client_user_id_ciphertext,
            DAY_ALIGNED_TIMESTAMP,
        )
        .expect("issued credential should be valid");

    let presentation = credential.present(&server_public_params, randomness4);

    // server verification of the credential presentation
    presentation
        .verify(
            group_members_without_requester,
            DAY_ALIGNED_TIMESTAMP,
            &server_secret_params,
        )
        .expect("credential should be valid for the timestamp given");
}

#[test]
fn test_empty_credential_can_be_issued_and_received() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];

    // first set up a group
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);

    let group_secret_params = zkgroup::groups::GroupSecretParams::generate(randomness1);
    let client_user_id_ciphertext = group_secret_params.encrypt_service_id(client_user_id.into());

    // server generated materials; issuance request -> issuance response
    let server_secret_params = zkgroup::ServerSecretParams::generate(randomness2);
    let credential_response = GroupSendCredentialResponse::issue_credential(
        [client_user_id_ciphertext],
        &client_user_id_ciphertext,
        DAY_ALIGNED_TIMESTAMP,
        &server_secret_params,
        randomness3,
    )
    .expect("valid request");

    let server_public_params = server_secret_params.get_public_params();
    let _credential = credential_response
        .receive(
            &server_public_params,
            &group_secret_params,
            [client_user_id.into()],
            client_user_id.into(),
            DAY_ALIGNED_TIMESTAMP,
        )
        .expect("issued credential should be valid");
}

#[test]
fn test_client_rejects_bad_expirations() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];

    // first set up a group
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);

    let moxie_user_id =
        libsignal_core::Aci::from(uuid::uuid!("e36fdce7-36da-4c6f-a21b-9afe2b754650"));
    let brian_user_id =
        libsignal_core::Aci::from(uuid::uuid!("8c78cd2a-16ff-427d-83dc-1a5e36ce713d"));

    let group_members = [
        client_user_id.into(),
        moxie_user_id.into(),
        brian_user_id.into(),
    ];

    let group_secret_params = zkgroup::groups::GroupSecretParams::generate(randomness1);
    let ciphertexts: Vec<_> = group_members
        .iter()
        .map(|member| group_secret_params.encrypt_service_id(*member))
        .collect();
    let client_user_id_ciphertext = group_secret_params.encrypt_service_id(client_user_id.into());

    let server_secret_params = zkgroup::ServerSecretParams::generate(randomness2);
    let server_public_params = server_secret_params.get_public_params();

    let expect_credential_rejected = |now: zkgroup::Timestamp, expiration: zkgroup::Timestamp| {
        let credential_response = GroupSendCredentialResponse::issue_credential(
            ciphertexts.clone(),
            &client_user_id_ciphertext,
            expiration,
            &server_secret_params,
            randomness3,
        )
        .expect("valid request");
        assert!(
            credential_response
                .receive(
                    &server_public_params,
                    &group_secret_params,
                    group_members,
                    client_user_id.into(),
                    now,
                )
                .is_err(),
            "now: {now}, expiration: {expiration}"
        );
    };
    expect_credential_rejected(DAY_ALIGNED_TIMESTAMP, DAY_ALIGNED_TIMESTAMP + 1);
    expect_credential_rejected(
        DAY_ALIGNED_TIMESTAMP,
        DAY_ALIGNED_TIMESTAMP + 8 * SECONDS_PER_DAY,
    );
    expect_credential_rejected(
        DAY_ALIGNED_TIMESTAMP,
        DAY_ALIGNED_TIMESTAMP + 1000 * SECONDS_PER_DAY,
    );
}
