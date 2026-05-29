//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::avatars::AvatarUploadCredentialRequestContext;
use zkgroup::generic_server_params::GenericServerSecretParams;
use zkgroup::zk_credential_key::ZkCredentialKeyPair;
use zkgroup::{RANDOMNESS_LEN, RandomnessBytes, Timestamp};

const DAY_ALIGNED_TIMESTAMP: Timestamp = Timestamp::from_epoch_seconds(1681344000); // 2023-04-13 00:00:00 UTC
const ACI: uuid::Uuid = uuid::uuid!("c0fc16e4-bae5-4343-9f0d-e7ecf4251343");
const ROTATION_ID: u64 = 1;
const SERVER_SECRET_RAND: RandomnessBytes = [0xA0; RANDOMNESS_LEN];
const HOLDER_REQUEST_RAND: RandomnessBytes = [0xA1; RANDOMNESS_LEN];
const ISSUER_RESPONSE_RAND: RandomnessBytes = [0xA2; RANDOMNESS_LEN];
const HOLDER_PRESENT_RAND: RandomnessBytes = [0xA3; RANDOMNESS_LEN];
const HOLDER_ZK_CRED_KEY_RAND: RandomnessBytes = [0x42; RANDOMNESS_LEN];

#[test]
fn avatar_upload_flow_with_holder_issuer_and_verifier() {
    let holder_aci = libsignal_core::Aci::from(ACI);
    // The holder's long-term Ristretto ZK credential key. The issuer stores the
    // public half against the holder's account.
    let holder_zk_credential_key_pair = ZkCredentialKeyPair::generate(HOLDER_ZK_CRED_KEY_RAND);
    let holder_zk_credential_key_pub = holder_zk_credential_key_pair.public_key();

    let issuer_secret_params = GenericServerSecretParams::generate(SERVER_SECRET_RAND);
    let issuer_public_params = issuer_secret_params.get_public_params();

    // Holder: prepare a full issuance request for Cm derived from the account ACI, ZK credential
    // key, and the rotation_id the holder already received when it set its ZK credential key.
    let request_context = AvatarUploadCredentialRequestContext::new(
        holder_aci,
        &holder_zk_credential_key_pair,
        ROTATION_ID,
        HOLDER_REQUEST_RAND,
    );
    let request = request_context.get_request();

    // Issuer: authenticate the account, look up the account's ZK credential public key and its
    // rotation_id, verify the Cm well-formedness proof in the request against that rotation_id, and
    // issue the blinded credential.
    let response = request
        .issue(
            holder_aci,
            &holder_zk_credential_key_pub,
            ROTATION_ID,
            DAY_ALIGNED_TIMESTAMP,
            &issuer_secret_params,
            ISSUER_RESPONSE_RAND,
        )
        .expect("issuer should accept a well-formed request");

    // Holder: verify the issuer's blinded issuance response and unblind the credential.
    let credential = request_context
        .receive(response, &issuer_public_params, DAY_ALIGNED_TIMESTAMP)
        .expect("holder should accept a valid issuance response");

    // Holder: present the credential to a separate verifying service, revealing only Cm and the
    // standard presentation proof needed to validate the credential.
    let presentation = credential.present(&issuer_public_params, HOLDER_PRESENT_RAND);

    // Verifier: validate the presentation against the issuer's server parameters. The verifier
    // learns Cm from the presentation and can use it as the anonymous ratelimiting key.
    presentation
        .verify(DAY_ALIGNED_TIMESTAMP, &issuer_secret_params)
        .expect("verifier should accept a valid presentation");

    assert_eq!(credential.cm(), presentation.cm());
    assert_eq!(DAY_ALIGNED_TIMESTAMP, presentation.redemption_time());
}
