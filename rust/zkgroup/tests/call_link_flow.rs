//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use test_case::test_case;
use zkgroup::call_links::CallLinkAuthCredentialResponse;
use zkgroup::generic_server_params::{
    GenericServerSecretParams, GenericServerSecretParamsLegacy, GenericServerSecretParamsStandard,
};
use zkgroup::{RANDOMNESS_LEN, RandomnessBytes, SECONDS_PER_DAY, Timestamp, UUID_LEN};

const DAY_ALIGNED_TIMESTAMP: Timestamp = Timestamp::from_epoch_seconds(1681344000); // 2023-04-13 00:00:00 UTC

fn choose_params<'a, T: 'static>(
    legacy_params: &'a GenericServerSecretParams,
    standard_params: &'a GenericServerSecretParams,
) -> (&'a GenericServerSecretParams, &'a GenericServerSecretParams) {
    match std::any::TypeId::of::<T>() {
        x if x == std::any::TypeId::of::<GenericServerSecretParamsLegacy>() => {
            (legacy_params, standard_params)
        }
        x if x == std::any::TypeId::of::<GenericServerSecretParamsStandard>() => {
            (standard_params, legacy_params)
        }
        _ => unreachable!(),
    }
}

#[test_case(PhantomData::<GenericServerSecretParamsLegacy>)]
#[test_case(PhantomData::<GenericServerSecretParamsStandard>)]
fn test_create_call_link_request_response<T: 'static>(_: PhantomData<T>) {
    let randomness0: RandomnessBytes = [0x42u8; RANDOMNESS_LEN];
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];
    let randomness4: RandomnessBytes = [0x46u8; RANDOMNESS_LEN];

    // client receives in response to initial request
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP;

    // known to client and redemption server
    let room_id = b"a very special room";

    // client generated materials; issuance request
    let request_context =
        zkgroup::call_links::CreateCallLinkCredentialRequestContext::new(room_id, randomness0);
    let request = request_context.get_request();

    // server generated materials; issuance request -> issuance response
    let legacy_server_secret_params = GenericServerSecretParamsLegacy::generate(randomness1).into();
    let standard_server_secret_params =
        GenericServerSecretParamsStandard::generate(randomness1).into();
    let (chosen_server_secret_params, other_server_secret_params) =
        choose_params::<T>(&legacy_server_secret_params, &standard_server_secret_params);
    let blinded_credential = request.issue(
        client_user_id,
        timestamp,
        chosen_server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    let server_public_params = chosen_server_secret_params.get_public_params();
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
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect("presentation should be valid");
    presentation
        .verify_against_appropriate_params(
            room_id,
            timestamp,
            &legacy_server_secret_params,
            &standard_server_secret_params,
            &client_public_params,
        )
        .expect("right params should be chosen");

    // Check some obvious failure cases.
    presentation
        .verify(
            room_id,
            timestamp.sub_seconds(1),
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid before its timestamp");
    presentation
        .verify(
            room_id,
            timestamp.add_seconds(30 * 60 * 60),
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid after expiration (30 hours later)");

    presentation
        .verify(
            b"a much more boring room",
            timestamp,
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid for a different room");

    presentation
        .verify(
            room_id,
            timestamp,
            other_server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid with the wrong params");

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
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP.add_seconds(60 * 60); // not on a day boundary!

    // known to client and redemption server
    let room_id = b"a very special room";

    // client generated materials; issuance request
    let request_context =
        zkgroup::call_links::CreateCallLinkCredentialRequestContext::new(room_id, randomness0);
    let request = request_context.get_request();

    // server generated materials; issuance request -> issuance response
    let server_secret_params = GenericServerSecretParamsLegacy::generate(randomness1).into();
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

#[test_case(PhantomData::<GenericServerSecretParamsLegacy>)]
#[test_case(PhantomData::<GenericServerSecretParamsStandard>)]
fn test_auth_credential<T: 'static>(_: PhantomData<T>) {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];
    let randomness4: RandomnessBytes = [0x46u8; RANDOMNESS_LEN];

    // client receives in response to initial request
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP;

    // server generated materials; issuance request -> issuance response
    let legacy_server_secret_params = GenericServerSecretParamsLegacy::generate(randomness1).into();
    let standard_server_secret_params =
        GenericServerSecretParamsStandard::generate(randomness1).into();
    let (chosen_server_secret_params, other_server_secret_params) =
        choose_params::<T>(&legacy_server_secret_params, &standard_server_secret_params);
    let credential_response = CallLinkAuthCredentialResponse::issue_credential(
        client_user_id,
        timestamp,
        chosen_server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    let server_public_params = chosen_server_secret_params.get_public_params();
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
        .verify(
            timestamp,
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect("credential should be valid for the timestamp given");
    presentation
        .verify(
            timestamp.add_seconds(SECONDS_PER_DAY),
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect("credential should be valid even an entire day later");
    presentation
        .verify_against_appropriate_params(
            timestamp,
            &legacy_server_secret_params,
            &standard_server_secret_params,
            &client_public_params,
        )
        .expect("right params should be chosen");

    // Check some error cases.
    presentation
        .verify(
            timestamp.add_seconds(2 * SECONDS_PER_DAY + 1),
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should expire more than two days later");
    presentation
        .verify(
            timestamp.sub_seconds(SECONDS_PER_DAY + 1),
            chosen_server_secret_params,
            &client_public_params,
        )
        .expect_err("credential should not be valid more than a day early");
    presentation
        .verify(timestamp, other_server_secret_params, &client_public_params)
        .expect_err("credential should not be valid with the wrong params");

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
    let client_user_id = libsignal_core::Aci::from_uuid_bytes([0x04u8; UUID_LEN]);
    let timestamp: Timestamp = DAY_ALIGNED_TIMESTAMP.add_seconds(60 * 60); // not on a day boundary!

    // server generated materials; issuance request -> issuance response
    let server_secret_params = GenericServerSecretParamsLegacy::generate(randomness1).into();
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
