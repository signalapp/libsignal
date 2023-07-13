//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::call_links::CallLinkAuthCredentialResponse;
use zkgroup::{RandomnessBytes, Timestamp, RANDOMNESS_LEN, SECONDS_PER_DAY, UUID_LEN};

const DAY_ALIGNED_TIMESTAMP: Timestamp = 1681344000; // 2023-04-13 00:00:00 UTC

#[test]
fn test_create_call_link_request_response() {
    let randomness0: RandomnessBytes = [0x42u8; RANDOMNESS_LEN];
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];
    let randomness4: RandomnessBytes = [0x46u8; RANDOMNESS_LEN];

    // client receives in response to initial request
    let client_user_id = libsignal_protocol::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP;

    // known to client and redemption server
    let room_id = b"a very special room";

    // client generated materials; issuance request
    let request_context =
        zkgroup::call_links::CreateCallLinkCredentialRequestContext::new(room_id, randomness0);
    let request = request_context.get_request();

    // server generated materials; issuance request -> issuance response
    let server_secret_params =
        zkgroup::generic_server_params::GenericServerSecretParams::generate(randomness1);
    let blinded_credential = request.issue(
        client_user_id,
        timestamp,
        &server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    let server_public_params = server_secret_params.get_public_params();
    let credential = request_context
        .receive(blinded_credential, client_user_id, &server_public_params)
        .expect("credential should be valid");

    let client_secret_params =
        zkgroup::call_links::CallLinkSecretParams::derive_from_root_key(&randomness3);

    let presentation = credential.present(
        room_id,
        client_user_id,
        &server_public_params,
        &client_secret_params,
        randomness4,
    );

    // server verification of the credential presentation
    let client_public_params = client_secret_params.get_public_params();
    presentation
        .verify(
            room_id,
            timestamp,
            &server_secret_params,
            &client_public_params,
        )
        .expect("presentation should be valid");

    // Check some obvious failure cases.
    presentation
        .verify(
            room_id,
            timestamp - 1,
            &server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid before its timestamp");
    presentation
        .verify(
            room_id,
            timestamp + 30 * 60 * 60,
            &server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid after expiration (30 hours later)");

    presentation
        .verify(
            b"a much more boring room",
            timestamp,
            &server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid for a different room");

    // And if the server made this information available to the client...
    assert_eq!(
        client_user_id,
        client_secret_params
            .decrypt_uid(presentation.get_user_id())
            .expect("user ID should match")
    );
}

#[test]
fn test_create_call_link_enforces_timestamp_granularity() {
    let randomness0: RandomnessBytes = [0x42u8; RANDOMNESS_LEN];
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];

    // client receives in response to initial request
    let client_user_id = libsignal_protocol::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP + 60 * 60; // not on a day boundary!

    // known to client and redemption server
    let room_id = b"a very special room";

    // client generated materials; issuance request
    let request_context =
        zkgroup::call_links::CreateCallLinkCredentialRequestContext::new(room_id, randomness0);
    let request = request_context.get_request();

    // server generated materials; issuance request -> issuance response
    let server_secret_params =
        zkgroup::generic_server_params::GenericServerSecretParams::generate(randomness1);
    let blinded_credential = request.issue(
        client_user_id,
        timestamp,
        &server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    assert!(
        request_context
            .receive(
                blinded_credential,
                client_user_id,
                &server_secret_params.get_public_params()
            )
            .is_err(),
        "client should require that timestamp is on a day boundary"
    );
}

#[test]
fn test_auth_credential() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];
    let randomness4: RandomnessBytes = [0x46u8; RANDOMNESS_LEN];

    // client receives in response to initial request
    let client_user_id = libsignal_protocol::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP;

    // server generated materials; issuance request -> issuance response
    let server_secret_params =
        zkgroup::generic_server_params::GenericServerSecretParams::generate(randomness1);
    let credential_response = CallLinkAuthCredentialResponse::issue_credential(
        client_user_id,
        timestamp,
        &server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    let server_public_params = server_secret_params.get_public_params();
    let credential = credential_response
        .receive(client_user_id, timestamp, &server_public_params)
        .expect("issued credential should be valid");

    let client_secret_params =
        zkgroup::call_links::CallLinkSecretParams::derive_from_root_key(&randomness3);

    let presentation = credential.present(
        client_user_id,
        timestamp,
        &server_public_params,
        &client_secret_params,
        randomness4,
    );

    // server verification of the credential presentation
    let client_public_params = client_secret_params.get_public_params();
    presentation
        .verify(timestamp, &server_secret_params, &client_public_params)
        .expect("credential should be valid for the timestamp given");
    presentation
        .verify(
            timestamp + SECONDS_PER_DAY,
            &server_secret_params,
            &client_public_params,
        )
        .expect("credential should be valid even an entire day later");

    // Check some error cases.
    presentation
        .verify(
            timestamp + 2 * SECONDS_PER_DAY + 1,
            &server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should expire more than two days later");
    presentation
        .verify(
            timestamp - SECONDS_PER_DAY - 1,
            &server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid more than a day early");

    // Check the user ID ciphertext.
    assert_eq!(
        client_user_id,
        client_secret_params
            .decrypt_uid(presentation.get_user_id())
            .expect("user ID should match")
    );
}

#[test]
fn test_auth_credential_enforces_timestamp_granularity() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];

    // client receives in response to initial request
    let client_user_id = libsignal_protocol::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP + 60 * 60; // not on a day boundary!

    // server generated materials; issuance request -> issuance response
    let server_secret_params =
        zkgroup::generic_server_params::GenericServerSecretParams::generate(randomness1);
    let credential_response = CallLinkAuthCredentialResponse::issue_credential(
        client_user_id,
        timestamp,
        &server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    assert!(
        credential_response
            .receive(
                client_user_id,
                timestamp,
                &server_secret_params.get_public_params()
            )
            .is_err(),
        "client should reject timestamp"
    );
}
