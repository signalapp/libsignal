//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::{RandomnessBytes, Timestamp, RANDOMNESS_LEN, SECONDS_PER_DAY, UUID_LEN};

const DAY_ALIGNED_TIMESTAMP: Timestamp = Timestamp::from_epoch_seconds(1681344000); // 2023-04-13 00:00:00 UTC

#[test]
fn test_endorsement() {
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
    let group_members_without_requester = [brian_user_id.into(), moxie_user_id.into()];

    let group_secret_params = zkgroup::groups::GroupSecretParams::generate(randomness1);
    let ciphertexts: Vec<_> = group_members
        .iter()
        .map(|member| group_secret_params.encrypt_service_id(*member))
        .collect();

    // server generated materials; issuance request -> issuance response
    let server_secret_params = zkgroup::ServerSecretParams::generate(randomness2);
    let todays_key = zkgroup::groups::GroupSendDerivedKeyPair::for_expiration(
        DAY_ALIGNED_TIMESTAMP.add_seconds(SECONDS_PER_DAY),
        &server_secret_params,
    );

    // Generate a response to test receive_with_service_ids:
    {
        let response = zkgroup::groups::GroupSendEndorsementsResponse::issue(
            ciphertexts.iter().copied(),
            &todays_key,
            randomness3,
        );

        // client generated materials; issuance response -> redemption request
        let server_public_params = server_secret_params.get_public_params();
        let expiration = response.expiration();
        let endorsements: Vec<_> = response
            .receive_with_service_ids(
                group_members,
                DAY_ALIGNED_TIMESTAMP,
                &group_secret_params,
                &server_public_params,
            )
            .expect("issued endorsements should be valid")
            .into_iter()
            .map(|received| received.decompressed)
            .collect();

        let combined_endorsements =
            zkgroup::groups::GroupSendEndorsement::combine(endorsements.clone())
                .remove(&endorsements[0]);

        let token = combined_endorsements
            .to_token(&group_secret_params)
            .into_full_token(expiration);

        // server verification of the credential presentation
        assert_eq!(token.expiration(), expiration);
        token
            .verify(
                group_members_without_requester,
                DAY_ALIGNED_TIMESTAMP,
                &todays_key,
            )
            .expect("credential should be valid for the timestamp given");
    }

    // Try again for receive_with_ciphertexts:
    {
        let response = zkgroup::groups::GroupSendEndorsementsResponse::issue(
            ciphertexts.iter().copied(),
            &todays_key,
            randomness3,
        );

        // client generated materials; issuance response -> redemption request
        let server_public_params = server_secret_params.get_public_params();
        let expiration = response.expiration();
        let endorsements: Vec<_> = response
            .receive_with_ciphertexts(
                ciphertexts.iter().copied(),
                DAY_ALIGNED_TIMESTAMP,
                &server_public_params,
            )
            .expect("issued endorsements should be valid")
            .into_iter()
            .map(|received| received.decompressed)
            .collect();

        let combined_endorsements =
            zkgroup::groups::GroupSendEndorsement::combine(endorsements.clone())
                .remove(&endorsements[0]);

        let token = combined_endorsements
            .to_token(&group_secret_params)
            .into_full_token(expiration);

        // server verification of the credential presentation
        assert_eq!(token.expiration(), expiration);
        token
            .verify(
                group_members_without_requester,
                DAY_ALIGNED_TIMESTAMP,
                &todays_key,
            )
            .expect("credential should be valid for the timestamp given");
    }
}

#[test]
fn test_single_member_group() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];

    // first set up a group
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);

    let group_secret_params = zkgroup::groups::GroupSecretParams::generate(randomness1);
    let client_user_id_ciphertext = group_secret_params.encrypt_service_id(client_user_id.into());

    // server generated materials; issuance request -> issuance response
    let server_secret_params = zkgroup::ServerSecretParams::generate(randomness2);
    let todays_key = zkgroup::groups::GroupSendDerivedKeyPair::for_expiration(
        DAY_ALIGNED_TIMESTAMP.add_seconds(SECONDS_PER_DAY),
        &server_secret_params,
    );
    let response = zkgroup::groups::GroupSendEndorsementsResponse::issue(
        [client_user_id_ciphertext],
        &todays_key,
        randomness3,
    );

    // client generated materials; issuance response -> redemption request
    let server_public_params = server_secret_params.get_public_params();
    let _endorsements = response
        .receive_with_service_ids(
            [client_user_id.into()],
            DAY_ALIGNED_TIMESTAMP,
            &group_secret_params,
            &server_public_params,
        )
        .expect("issued endorsements should be valid");
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

    let server_secret_params = zkgroup::ServerSecretParams::generate(randomness2);
    let server_public_params = server_secret_params.get_public_params();

    let expect_credential_rejected = |now: zkgroup::Timestamp, expiration: zkgroup::Timestamp| {
        let key = zkgroup::groups::GroupSendDerivedKeyPair::for_expiration(
            expiration,
            &server_secret_params,
        );
        let response = zkgroup::groups::GroupSendEndorsementsResponse::issue(
            ciphertexts.iter().cloned(),
            &key,
            randomness3,
        );

        assert!(
            response
                .receive_with_service_ids(
                    [client_user_id.into()],
                    now,
                    &group_secret_params,
                    &server_public_params,
                )
                .is_err(),
            "now: {now:?}, expiration: {expiration:?}"
        );
    };
    expect_credential_rejected(DAY_ALIGNED_TIMESTAMP, DAY_ALIGNED_TIMESTAMP);
    expect_credential_rejected(
        DAY_ALIGNED_TIMESTAMP,
        DAY_ALIGNED_TIMESTAMP.sub_seconds(SECONDS_PER_DAY),
    );
    expect_credential_rejected(DAY_ALIGNED_TIMESTAMP, DAY_ALIGNED_TIMESTAMP.add_seconds(1));
    expect_credential_rejected(
        DAY_ALIGNED_TIMESTAMP,
        DAY_ALIGNED_TIMESTAMP.add_seconds(8 * SECONDS_PER_DAY),
    );
    expect_credential_rejected(
        DAY_ALIGNED_TIMESTAMP,
        DAY_ALIGNED_TIMESTAMP.add_seconds(1000 * SECONDS_PER_DAY),
    );
}
