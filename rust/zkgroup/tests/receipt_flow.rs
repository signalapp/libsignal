//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::api::receipts::ReceiptCredentialPresentation;
use zkgroup::common::sho::Sho;
use zkgroup::crypto::proofs::{ReceiptCredentialIssuanceProof, ReceiptCredentialPresentationProof};
use zkgroup::crypto::receipt_struct::ReceiptStruct;
use zkgroup::crypto::{credentials, receipt_credential_request};
use zkgroup::{
    RandomnessBytes, ReceiptLevel, ReceiptSerialBytes, ServerSecretParams, Timestamp,
    RANDOMNESS_LEN, RECEIPT_SERIAL_LEN,
};

#[test]
fn test_request_response() {
    let mut sho = Sho::new(b"Test_Receipt_Credential_Request", b"");

    // client receives in response to initial request
    let receipt_expiration_time: Timestamp = 42;
    let receipt_level: ReceiptLevel = 3;

    // known to client and redemption server
    let receipt_serial_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // client generated materials; issuance request
    let client_key_pair = receipt_credential_request::KeyPair::generate(&mut sho);
    let client_ciphertext = client_key_pair.encrypt(receipt_serial_bytes, &mut sho);
    let given_to_server_ciphertext = client_ciphertext.get_ciphertext();
    let given_to_server_public_key = client_key_pair.get_public_key();

    // server generated materials; issuance request -> issuance response
    let server_key_pair = credentials::KeyPair::generate(&mut sho);
    let blinded_receipt_credential = server_key_pair.create_blinded_receipt_credential(
        given_to_server_public_key,
        given_to_server_ciphertext,
        receipt_expiration_time,
        receipt_level,
        &mut sho,
    );
    let given_to_client_blinded_receipt_credential =
        blinded_receipt_credential.get_blinded_receipt_credential();
    let given_to_client_receipt_credential_issuance_proof = ReceiptCredentialIssuanceProof::new(
        server_key_pair,
        given_to_server_public_key,
        given_to_server_ciphertext,
        blinded_receipt_credential,
        receipt_expiration_time,
        receipt_level,
        &mut sho,
    );

    // client generated materials; issuance response -> redemption request
    let receipt_struct =
        ReceiptStruct::new(receipt_serial_bytes, receipt_expiration_time, receipt_level);
    given_to_client_receipt_credential_issuance_proof
        .verify(
            server_key_pair.get_public_key(),
            given_to_server_public_key,
            given_to_server_ciphertext,
            given_to_client_blinded_receipt_credential,
            receipt_struct,
        )
        .expect("issuance proof validity check failed");
    let receipt_credential = client_key_pair
        .decrypt_blinded_receipt_credential(given_to_client_blinded_receipt_credential);
    let receipt_credential_presentation_proof = ReceiptCredentialPresentationProof::new(
        server_key_pair.get_public_key(),
        receipt_credential,
        &mut sho,
    );

    // server verification of the credential presentation
    receipt_credential_presentation_proof
        .verify(server_key_pair, receipt_struct)
        .expect("presentation proof validity check failed");
}

/// Same as test_request_response but using the server params API.
#[test]
fn test_api() {
    let randomness0: RandomnessBytes = [0x42u8; RANDOMNESS_LEN];
    let randomness1: RandomnessBytes = [0x43u8; RANDOMNESS_LEN];
    let randomness2: RandomnessBytes = [0x44u8; RANDOMNESS_LEN];
    let randomness3: RandomnessBytes = [0x45u8; RANDOMNESS_LEN];
    let receipt_serial_bytes: ReceiptSerialBytes = [0x84u8; RECEIPT_SERIAL_LEN];
    let server_secret_params = ServerSecretParams::generate(randomness0);
    let server_public_params = server_secret_params.get_public_params();

    // client
    let context = server_public_params
        .create_receipt_credential_request_context(randomness1, receipt_serial_bytes);
    let request = context.get_request();

    // issuance server
    let receipt_expiration_time: Timestamp = 31337;
    let receipt_level: ReceiptLevel = 3;
    let response = server_secret_params.issue_receipt_credential(
        randomness2,
        &request,
        receipt_expiration_time,
        receipt_level,
    );

    // client
    let credential = server_public_params
        .receive_receipt_credential(&context, &response)
        .expect("Invalid Receipt Credential Issuance");
    let presentation =
        server_public_params.create_receipt_credential_presentation(randomness3, &credential);

    // redemption server
    server_secret_params
        .verify_receipt_credential_presentation(&presentation)
        .expect("Invalid Receipt Credential Presentation");

    assert_eq!(
        zkgroup::common::constants::RECEIPT_CREDENTIAL_REQUEST_CONTEXT_LEN,
        bincode::serialize(&context).unwrap().len(),
    );
    assert_eq!(
        zkgroup::common::constants::RECEIPT_CREDENTIAL_REQUEST_LEN,
        bincode::serialize(&request).unwrap().len(),
    );
    assert_eq!(
        zkgroup::common::constants::RECEIPT_CREDENTIAL_RESPONSE_LEN,
        bincode::serialize(&response).unwrap().len(),
    );
    assert_eq!(
        zkgroup::common::constants::RECEIPT_CREDENTIAL_LEN,
        bincode::serialize(&credential).unwrap().len(),
    );
    assert_eq!(
        zkgroup::common::constants::RECEIPT_CREDENTIAL_PRESENTATION_LEN,
        bincode::serialize(&presentation).unwrap().len(),
    );

    let mut presentation_bytes = bincode::serialize(&presentation).unwrap();
    // change it ever so slightly; maybe try a higher level for instance
    let i = presentation_bytes.len() - 17;
    presentation_bytes[i] += 1;
    let bad_presentation =
        bincode::deserialize::<ReceiptCredentialPresentation>(&presentation_bytes).unwrap();
    server_secret_params
        .verify_receipt_credential_presentation(&bad_presentation)
        .expect_err("This Presentation Should Be Bad");
}
