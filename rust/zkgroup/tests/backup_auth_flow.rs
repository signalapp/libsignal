//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::{RandomnessBytes, Timestamp, RANDOMNESS_LEN};

const DAY_ALIGNED_TIMESTAMP: Timestamp = Timestamp::from_epoch_seconds(1681344000); // 2023-04-13 00:00:00 UTC

#[test]
fn test_backup_auth_request_response() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];

    // client derives this from the their master key
    // The type annotation is not redundant; it indicates we are using the latest version of the
    // backup key struct.
    let backup_key: libsignal_account_keys::BackupKey =
        libsignal_account_keys::BackupKey([0x46u8; 32]);

    // known by the client and the issuing server (out of band), unknown to the verifying server
    let aci: libsignal_core::Aci = uuid::uuid!("c0fc16e4-bae5-4343-9f0d-e7ecf4251343").into();

    // client receives in response to initial request
    let redemption_time: Timestamp = DAY_ALIGNED_TIMESTAMP; // client validates it's day-aligned
    let backup_level = zkgroup::backups::BackupLevel::Free; // client validates it's a valid backup level
    let credential_type = zkgroup::backups::BackupCredentialType::Messages; // client validates it's for the right set of files

    // client generated materials; issuance request
    let request_context =
        zkgroup::backups::BackupAuthCredentialRequestContext::new(&backup_key, aci);
    let request = request_context.get_request();

    // server generated materials; issuance request -> issuance response
    let server_secret_params =
        zkgroup::generic_server_params::GenericServerSecretParams::generate(randomness1);
    let blinded_credential = request.issue(
        redemption_time,
        backup_level,
        credential_type,
        &server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    let server_public_params = server_secret_params.get_public_params();
    let credential = request_context
        .receive(blinded_credential, &server_public_params, redemption_time)
        .expect("credential should be valid");

    assert_eq!(credential.backup_level(), backup_level);
    assert_eq!(credential.credential_type(), credential_type);

    let presentation = credential.present(&server_public_params, randomness3);

    // server verification of the credential presentation
    presentation
        .verify(redemption_time, &server_secret_params)
        .expect("presentation should be valid");
}
