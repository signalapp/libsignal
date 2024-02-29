//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::{RandomnessBytes, ReceiptLevel, Timestamp, RANDOMNESS_LEN};

const DAY_ALIGNED_TIMESTAMP: Timestamp = 1681344000; // 2023-04-13 00:00:00 UTC

#[test]
fn test_backup_auth_request_response() {
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];

    // client derives this from the their master key
    let backup_key: [u8; 32] = [0x46u8; 32];

    // known by the client and the issuing server (out of band), unknown to the verifying server
    let aci: uuid::Uuid = uuid::uuid!("c0fc16e4-bae5-4343-9f0d-e7ecf4251343");

    // client receives in response to initial request
    let redemption_time: Timestamp = DAY_ALIGNED_TIMESTAMP; // client validates it's day-aligned
    let receipt_level: ReceiptLevel = 100; // client validates it's their expected receipt level

    // client generated materials; issuance request
    let request_context =
        zkgroup::backups::BackupAuthCredentialRequestContext::new(&backup_key, &aci);
    let request = request_context.get_request();

    // server generated materials; issuance request -> issuance response
    let server_secret_params =
        zkgroup::generic_server_params::GenericServerSecretParams::generate(randomness1);
    let blinded_credential = request.issue(
        redemption_time,
        receipt_level,
        &server_secret_params,
        randomness2,
    );

    // client generated materials; issuance response -> redemption request
    let server_public_params = server_secret_params.get_public_params();
    let credential = request_context
        .receive(blinded_credential, &server_public_params, receipt_level)
        .expect("credential should be valid");

    let presentation = credential.present(&server_public_params, randomness3);

    // server verification of the credential presentation
    presentation
        .verify(redemption_time, &server_secret_params)
        .expect("presentation should be valid");
}
