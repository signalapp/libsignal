//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::ristretto::RistrettoPoint;
use hex_literal::hex;
use sha2::Sha256;
use zkgroup::SECONDS_PER_DAY;

/// Simple wrapper around `assert_eq` that prints the hex-encoded values on
/// failure.
macro_rules! assert_hex_eq {
    ($lhs:expr, $rhs: expr) => {
        assert_eq!(
            &$lhs,
            &$rhs,
            "{} = {}, {} = {}",
            stringify!($lhs),
            hex::encode(&$lhs),
            stringify!($rhs),
            hex::encode(&$rhs),
        );
    };
}

#[test]
fn test_lizard() {
    let p = RistrettoPoint::lizard_encode::<Sha256>(&zkgroup::common::constants::TEST_ARRAY_16);
    let data_out = p.lizard_decode::<Sha256>();
    assert_hex_eq!(data_out.unwrap(), zkgroup::common::constants::TEST_ARRAY_16);
}

const AUTH_CREDENTIAL_PRESENTATION_V1:&[u8] = &hex!( "000cde979737ed30bbeb16362e4e076945ce02069f727b0ed4c3c33c011e82546e1cdf081fbdf37c03a851ad060bdcbf6378cb4cb16dc3154d08de5439b5323203729d1841b517033af2fd177d30491c138ae723655734f6e5cc01c00696f4e92096d8c33df26ba2a820d42e9735d30f8eeef96d399079073c099f7035523bfe716638659319d3c36ad34c00ef8850f663c4d93030235074312a8878b6a5c5df4fbc7d32935278bfa5996b44ab75d6f06f4c30b98640ad5de74742656c8977567de000000000000000fde69f82ad2dcb4909650ac6b2573841af568fef822b32b45f625a764691a704d11b6f385261468117ead57fa623338e21c66ed846ab65809fcac158066d8e0e444077b99540d886e7dc09555dd6faea2cd3697f1e089f82d54e5d0fe4a185008b5cbc3979391ad71686bc03be7b00ea7e42c08d9f1d75c3a56c27ae2467b80636c0b5343eda7cd578ba88ddb7a0766568477fed63cf531862122c6c15b4a707973d41782cfc0ef4fe6c3115988a2e339015938d2df0a5d30237a2592cc10c05a9e4ef6b695bca99736b1a49ea39606a381ecfb05efe60d28b54823ec5a3680c765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547440e20100");

const AUTH_CREDENTIAL_PRESENTATION_V3_RESULT: &[u8] = &hex!("02ec2374624ee8de07393f4c4f625afe1793a3fe0cfcf19a447ee93667e52dc7763800382c6ee41e49bb60c40cbd76657e1f6c737f502d6f47abe16bd4efab1f71948d7634771cd04573a75f3c8e77e70c55f5550753ad077cfe5bb3edee0b0e2ab8087285653df8415b9fea2f5410c4094059a2217e280865bfeba660538da20786346da334c67bfc4d706f725117a75e60c6fa242e2735fc2361d129b7ab793a100a6a4917959f0f87ef75ef35350e6da9d7d638cf8cf9f106c94734a32b85337441d22a99cf08c24d11f4e7beddbf7fc91a10145215b950a2b78e7fbbc7707faa0de254125cbac98f021467f540151c577366800fee1fc6ea4730ee58cd7460e0000000000000009ef87a5ea87d8bb00516623394ff9b82ced69477360c21e00e44da187129d80d414da3f3d26d2d22af93d659c4816c75046e597ab614f09edda581b08162070da8c1234c65268496db7ba8aa3b81e67336f53174926573ba5a007bbaa2a23b01d09fa41998bdfeb49e4e7d077b81693421c05af81c53a58681035b72f9b6eb04e366da64ca95f5277e1af3aa2f915accd120cad67578f7a4d075bd3cc91c07095db54b0203955419677723ad3ee7ff95f3858558aeb040427cb81ab02be7e60cea45dc2f4ad12e70d32f67741228fd5789b7110b4a3169c13ad66e4c9aa3cd08765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f525474de749a0fef17b06bbce74ca5d0f7a0c45f443a1901f1e3e016d3548e50a2fa19ce6b27ac467ed9c9f5018b2a4456b6c2b1a91454422fdd473c9636a8459e1c170060c77b02000000");

const AUTH_CREDENTIAL_PRESENTATION_V3_RESULT_WITH_PNI_AS_ACI: &[u8] = &hex!("02ec2374624ee8de07393f4c4f625afe1793a3fe0cfcf19a447ee93667e52dc7763800382c6ee41e49bb60c40cbd76657e1f6c737f502d6f47abe16bd4efab1f71948d7634771cd04573a75f3c8e77e70c55f5550753ad077cfe5bb3edee0b0e2ab8087285653df8415b9fea2f5410c4094059a2217e280865bfeba660538da207f8879e4afc64bb8390b8ddc4676186870e5a345a85325ab1dfd98be019531a16100a6a4917959f0f87ef75ef35350e6da9d7d638cf8cf9f106c94734a32b85337441d22a99cf08c24d11f4e7beddbf7fc91a10145215b950a2b78e7fbbc7707f8eebb47578ae1c9da0af2f74eb2675c8aec04c6df80b566ed3ced45cd9520453e000000000000000deaff541b1ef79a282ca4e553ed1e2cc3e1c95510c6d3b9037a5a672411a350e825cb0fdbf4cc517ddaa482b4b2467ec91362544153b83191aba0b413ca0b00034a1a949d107b3e74156d5d9b196480ee37f0df1b42a136ffea8968139a0aa01595fc8e20231f3587806c9c4713c87acc8fef60d3f1a849d184dd495588bf303b1fce75e4c7a177c644b62d2adbc042c7798cfd6c43921541649d23a90e87d0f14303050fcc15d975aef8d56bfabcf55b05e9344916bb6aeb4351898df158903be4fefc933c6a2032e343a59f1ce1e1f4de8f381a59f35f98c3c224936fe5404765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f525474fe74409060615679fc115473683d63abd9ced46c7f2ad736046de5a2c7d2522f122895597049cfd7cc5beb6dc72aa990ae9a62ec8e256a1cbf5f3f284233bb070060c77b02000000");

const AUTH_CREDENTIAL_PRESENTATION_V4_RESULT: &[u8] = &hex!("035e3e79afda8dc0d489fcf7c78f71e1502f2e06e8aeb20149046f85b3004d3f7f982d57dfad49cd1e6c335755cef4cc5e8d3de1eb4f5e8f24d71cf9f2220ae750f47181d71aaabbd48a1916813ec08eea935eb013395bf72f9139da8ef4f9530d05000000000000007a080544e6ee8ee2ff0dc298f18841103a9f9ec38631df8682e241755f86f74e26301872f4f32a9bb80f5b17651c0c83253a8013532384061a1febf79e58e60fa215b31da678305fa2a271655e35824630d0804680ec0bf29b1c775652683c3a5cec537c3514df730f267371d909f29cc6252af30afe3ea846c0cf56478bdc5b7a7f983ea7c24ecef4b371286a6414b2c38a57a7f59a9df33e430736c1a2ca14e00000000000000015416082ff7e3a741a4c3c31be3c95d4a31f2cf742685e0b17cd7f7205230e0e4e67b4b6ed45e705de13a1cb7170897bb32c9db6f9a1108fddfc7fae9eb2ca0c5fc3d8ccbd79d992eeed333626a1f0c37f0b25625955611e5ba33c782c50550045923582280cd93c3e9555b4e36eec20993f60b6aeb9ddb7f2856c4659546f037b33534a0292c77a501a70796f24ff37c8311bdfea8bb6c78f909563fe6e3b0386f36adc92090694ebb106a837bac046ad26e2472ee16408e9fd84269fd78c00c5dde91fcf202a6afad3441b9e2a34f4831d5bf560c81b38d951cb7c88e4d701765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f525474de749a0fef17b06bbce74ca5d0f7a0c45f443a1901f1e3e016d3548e50a2fa19ce6b27ac467ed9c9f5018b2a4456b6c2b1a91454422fdd473c9636a8459e1c170060c77b02000000");

const PROFILE_KEY_CREDENTIAL_PRESENTATION_V3_RESULT: &[u8] = &hex!("02fc58a4f2c9bd736238abfc28890c8b2363d084bee430692f05ee559bd37dea3378949e72b271fe0d815b6d908035106cd670b45892df40780c62c37fae106c41be38371fe042a4d4f697db112972d79204b3d48d1253d3231c22926e107f661d40897cb7fdb4777c1680a57008655db71efaac1f69cd9ddf8cda33b226662d7ba443416281508fcdbb026d63f83168470a83e12803a6d2ee2c907343f2f6b063fe6bf0f17a032fabe61e77e904dfe7d3042125728c1984c86a094a0e3991ba554c1ebf604c14a8b13c384c5c01909656c114b24f9d3615d3b14bde7ce9cf126aca3e073e804b2016f7c5affa158a3a68ed9024c6880ecb441a346e7e91aedd6240010000000000002e70f27fb3f4c58cb40dfe58ce1d122312969426abb0bbb820bfbc5ff61d400a419d5ddb7c30c546427273d4fca3096ee4dd2fd03ccbbd26304ffcfe54fef50db8538177ebc61117a222253b4d4189f795abbde3b3d8a0a72d97b7750e0394010a01b474c3e942ef1ee807e17421689c6ca793c4f30b09c989b8a9679aee130eb034f64a34dbcaf12616970d2c8d58ca715bf5c4d42475fa6a1b82ba31574e072506652253e86cd783e30e1c06d2e861ba864a5373759472b31c5b26a8e46d062b8b5da2ec0a3ba499648e80f307728b7815aa60d167a0a9d01c2d2cbfb0a60ddc9dfc5343564b5f021fd1adba6d2a389e7c331bfffeed2a5d1887634323840574e49255a62d9e00ffc21f56afbb12fb9660e185f979223ec714c01e403a3a0a3276d0ef78182f12c092f5237befe3f0afea7693370788f854ec697e44c9bd02765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a7468069160000000000");

#[test]
fn test_auth_credential_presentation_v1_is_rejected() {
    assert!(
        zkgroup::auth::AnyAuthCredentialPresentation::new(AUTH_CREDENTIAL_PRESENTATION_V1).is_err()
    );
}

#[test]
fn test_integration_auth_with_pni() {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    // Random UID and issueTime
    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);
    let pni = libsignal_core::Pni::from_uuid_bytes(zkgroup::TEST_ARRAY_16_1);
    let redemption_time = 123456 * SECONDS_PER_DAY;

    // SERVER
    // Issue credential
    let randomness = zkgroup::TEST_ARRAY_32_2;
    let auth_credential_response = server_secret_params
        .issue_auth_credential_with_pni_as_service_id(randomness, aci, pni, redemption_time);

    // CLIENT
    let auth_credential = server_public_params
        .receive_auth_credential_with_pni_as_service_id(
            aci,
            pni,
            redemption_time,
            auth_credential_response.clone(),
        )
        .unwrap();

    assert!(server_public_params
        .receive_auth_credential_with_pni_as_aci(
            aci,
            pni,
            redemption_time,
            auth_credential_response.clone(),
        )
        .is_err());

    // Create and receive presentation
    let randomness = zkgroup::TEST_ARRAY_32_5;

    let presentation = server_public_params.create_auth_credential_with_pni_presentation(
        randomness,
        group_secret_params,
        auth_credential.clone(),
    );

    let presentation_bytes = &bincode::serialize(&presentation).unwrap();

    let presentation_any: zkgroup::auth::AnyAuthCredentialPresentation = presentation;

    let presentation_any_bytes = &bincode::serialize(&presentation_any).unwrap();

    assert_hex_eq!(
        AUTH_CREDENTIAL_PRESENTATION_V3_RESULT[..],
        presentation_bytes[..]
    );
    assert_hex_eq!(
        AUTH_CREDENTIAL_PRESENTATION_V3_RESULT[..],
        presentation_any_bytes[..]
    );

    let presentation_parsed = bincode::deserialize::<
        zkgroup::auth::AuthCredentialWithPniPresentation,
    >(presentation_bytes)
    .unwrap();

    assert!(
        presentation_any.get_pni_ciphertext().unwrap()
            == group_secret_params.encrypt_service_id(pni.into())
    );

    server_secret_params
        .verify_auth_credential_with_pni_presentation(
            group_public_params,
            &presentation_parsed,
            redemption_time,
        )
        .unwrap();

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time,
        )
        .unwrap();

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time - SECONDS_PER_DAY - 1,
        )
        .expect_err("credential not valid before redemption time (allowing for clock skew)");

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time + 2 * SECONDS_PER_DAY + 2,
        )
        .expect_err("credential not valid past deadline");

    // test encoding
    // these tests will also discover if the serialized sizes change,
    //   necessitating an update to the LEN constants
    let mut group_secret_params_bytes = [0u8; zkgroup::common::constants::GROUP_SECRET_PARAMS_LEN];
    let mut server_secret_params_bytes =
        [0u8; zkgroup::common::constants::SERVER_SECRET_PARAMS_LEN];
    let mut group_public_params_bytes = [0u8; zkgroup::common::constants::GROUP_PUBLIC_PARAMS_LEN];
    let mut server_public_params_bytes =
        [0u8; zkgroup::common::constants::SERVER_PUBLIC_PARAMS_LEN];
    let mut auth_credential_response_bytes =
        [0u8; zkgroup::common::constants::AUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN];
    let mut auth_credential_bytes = [0u8; zkgroup::common::constants::AUTH_CREDENTIAL_WITH_PNI_LEN];

    group_secret_params_bytes.copy_from_slice(&bincode::serialize(&group_secret_params).unwrap());
    server_secret_params_bytes.copy_from_slice(&bincode::serialize(&server_secret_params).unwrap());
    group_public_params_bytes.copy_from_slice(&bincode::serialize(&group_public_params).unwrap());
    server_public_params_bytes.copy_from_slice(&bincode::serialize(&server_public_params).unwrap());
    auth_credential_response_bytes
        .copy_from_slice(&bincode::serialize(&auth_credential_response).unwrap());
    auth_credential_bytes.copy_from_slice(&bincode::serialize(&auth_credential).unwrap());
}

#[test]
fn test_integration_auth_with_pni_using_pni_as_aci() {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    // Random UID and issueTime
    let aci = libsignal_core::Aci::from(uuid::Uuid::from_bytes(zkgroup::TEST_ARRAY_16));
    let pni = libsignal_core::Pni::from(uuid::Uuid::from_bytes(zkgroup::TEST_ARRAY_16_1));
    let redemption_time = 123456 * SECONDS_PER_DAY;

    // SERVER
    // Issue credential
    let randomness = zkgroup::TEST_ARRAY_32_2;
    let auth_credential_response = server_secret_params.issue_auth_credential_with_pni_as_aci(
        randomness,
        aci,
        pni,
        redemption_time,
    );

    // CLIENT
    let auth_credential = server_public_params
        .receive_auth_credential_with_pni_as_aci(
            aci,
            pni,
            redemption_time,
            auth_credential_response.clone(),
        )
        .unwrap();

    assert!(server_public_params
        .receive_auth_credential_with_pni_as_service_id(
            aci,
            pni,
            redemption_time,
            auth_credential_response,
        )
        .is_err());

    // Create and receive presentation
    let randomness = zkgroup::TEST_ARRAY_32_5;

    let presentation = server_public_params.create_auth_credential_with_pni_presentation(
        randomness,
        group_secret_params,
        auth_credential,
    );

    let presentation_bytes = &bincode::serialize(&presentation).unwrap();

    let presentation_any: zkgroup::auth::AnyAuthCredentialPresentation = presentation;

    let presentation_any_bytes = &bincode::serialize(&presentation_any).unwrap();

    assert_hex_eq!(
        AUTH_CREDENTIAL_PRESENTATION_V3_RESULT_WITH_PNI_AS_ACI[..],
        presentation_bytes[..]
    );

    assert_hex_eq!(
        AUTH_CREDENTIAL_PRESENTATION_V3_RESULT_WITH_PNI_AS_ACI[..],
        presentation_any_bytes[..]
    );

    let presentation_parsed = bincode::deserialize::<
        zkgroup::auth::AuthCredentialWithPniPresentation,
    >(presentation_bytes)
    .unwrap();

    assert!(
        presentation_any.get_pni_ciphertext().unwrap()
            == group_secret_params
                .encrypt_service_id(libsignal_core::Aci::from(uuid::Uuid::from(pni)).into())
    );

    server_secret_params
        .verify_auth_credential_with_pni_presentation(
            group_public_params,
            &presentation_parsed,
            redemption_time,
        )
        .unwrap();

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time,
        )
        .unwrap();

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time - SECONDS_PER_DAY - 1,
        )
        .expect_err("credential not valid before redemption time (allowing for clock skew)");

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time + 2 * SECONDS_PER_DAY + 2,
        )
        .expect_err("credential not valid past deadline");
}

#[test]
fn test_integration_auth_zkc() {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    // Random UID and issueTime
    let aci = libsignal_core::Aci::from(uuid::Uuid::from_bytes(zkgroup::TEST_ARRAY_16));
    let pni = libsignal_core::Pni::from(uuid::Uuid::from_bytes(zkgroup::TEST_ARRAY_16_1));
    let redemption_time = 123456 * SECONDS_PER_DAY;

    // SERVER
    // Issue credential
    let randomness = zkgroup::TEST_ARRAY_32_2;
    let auth_credential_response =
        zkgroup::auth::AuthCredentialWithPniZkcResponse::issue_credential(
            aci,
            pni,
            redemption_time,
            &server_secret_params,
            randomness,
        );

    // CLIENT
    let auth_credential = auth_credential_response
        .clone()
        .receive(aci, pni, redemption_time, &server_public_params)
        .unwrap();

    // Create and receive presentation
    let randomness = zkgroup::TEST_ARRAY_32_5;

    let presentation =
        auth_credential.present(&server_public_params, &group_secret_params, randomness);

    let presentation_bytes = &bincode::serialize(&presentation).unwrap();

    let presentation_any: zkgroup::auth::AnyAuthCredentialPresentation = presentation.into();

    let presentation_any_bytes = &bincode::serialize(&presentation_any).unwrap();

    assert_hex_eq!(
        AUTH_CREDENTIAL_PRESENTATION_V4_RESULT[..],
        presentation_bytes[..]
    );

    assert_hex_eq!(
        AUTH_CREDENTIAL_PRESENTATION_V4_RESULT[..],
        presentation_any_bytes[..]
    );

    let presentation_parsed = bincode::deserialize::<
        zkgroup::auth::AuthCredentialWithPniZkcPresentation,
    >(presentation_bytes)
    .unwrap();

    assert!(
        presentation_any.get_pni_ciphertext().unwrap()
            == group_secret_params.encrypt_service_id(pni.into())
    );

    presentation_parsed
        .verify(&server_secret_params, &group_public_params, redemption_time)
        .unwrap();

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time,
        )
        .unwrap();

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time - SECONDS_PER_DAY - 1,
        )
        .expect_err("credential not valid before redemption time (allowing for clock skew)");

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time + 2 * SECONDS_PER_DAY + 2,
        )
        .expect_err("credential not valid past deadline");

    // Test encoding, which will also detect if the serialized lengths change.
    let mut auth_credential_response_bytes =
        [0u8; zkgroup::common::constants::AUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN];
    let mut auth_credential_bytes = [0u8; zkgroup::common::constants::AUTH_CREDENTIAL_WITH_PNI_LEN];
    auth_credential_response_bytes
        .copy_from_slice(&bincode::serialize(&auth_credential_response).unwrap());
    auth_credential_bytes.copy_from_slice(&bincode::serialize(&auth_credential).unwrap());
}

#[test]
fn test_integration_expiring_profile() {
    // SERVER
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();

    // CLIENT
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);
    let profile_key =
        zkgroup::profiles::ProfileKey::create(zkgroup::common::constants::TEST_ARRAY_32_1);
    let profile_key_commitment = profile_key.get_commitment(aci);

    // Create context and request
    let randomness = zkgroup::TEST_ARRAY_32_3;

    let context = server_public_params.create_profile_key_credential_request_context(
        randomness,
        aci,
        profile_key,
    );
    let request = context.get_request();

    // SERVER

    let randomness = zkgroup::TEST_ARRAY_32_4;
    let expiration = 17u64 * 24 * 60 * 60;
    let current_time = expiration - 2 * 24 * 60 * 60;
    let response = server_secret_params
        .issue_expiring_profile_key_credential(
            randomness,
            &request,
            aci,
            profile_key_commitment,
            expiration,
        )
        .unwrap();

    // CLIENT
    // Gets stored profile credential

    let profile_key_credential = server_public_params
        .receive_expiring_profile_key_credential(&context, &response, current_time)
        .unwrap();

    // Create encrypted UID and profile key
    let uuid_ciphertext = group_secret_params.encrypt_service_id(aci.into());
    let plaintext = group_secret_params
        .decrypt_service_id(uuid_ciphertext)
        .unwrap();
    assert_eq!(plaintext, aci);

    let profile_key_ciphertext = group_secret_params.encrypt_profile_key(profile_key, aci);
    let decrypted_profile_key = group_secret_params
        .decrypt_profile_key(profile_key_ciphertext, aci)
        .unwrap();

    assert_hex_eq!(decrypted_profile_key.get_bytes(), profile_key.get_bytes());

    // Create presentation
    let randomness = zkgroup::TEST_ARRAY_32_5;

    let presentation = server_public_params.create_expiring_profile_key_credential_presentation(
        randomness,
        group_secret_params,
        profile_key_credential,
    );
    assert_eq!(expiration, presentation.get_expiration_time());
    let presentation_bytes = &bincode::serialize(&presentation).unwrap();

    let presentation_any: zkgroup::profiles::AnyProfileKeyCredentialPresentation =
        presentation.into();
    let presentation_any_bytes = &bincode::serialize(&presentation_any).unwrap();

    assert_hex_eq!(
        PROFILE_KEY_CREDENTIAL_PRESENTATION_V3_RESULT[..],
        presentation_bytes[..]
    );

    assert_hex_eq!(
        PROFILE_KEY_CREDENTIAL_PRESENTATION_V3_RESULT[..],
        presentation_any_bytes[..]
    );

    server_secret_params
        .verify_profile_key_credential_presentation(
            group_public_params,
            &presentation_any,
            expiration - 5,
        )
        .unwrap();

    assert!(server_secret_params
        .verify_profile_key_credential_presentation(
            group_public_params,
            &presentation_any,
            expiration,
        )
        .is_err());
    assert!(server_secret_params
        .verify_profile_key_credential_presentation(
            group_public_params,
            &presentation_any,
            expiration + 5,
        )
        .is_err());

    let presentation_parsed =
        zkgroup::profiles::AnyProfileKeyCredentialPresentation::new(presentation_bytes).unwrap();
    server_secret_params
        .verify_profile_key_credential_presentation(
            group_public_params,
            &presentation_parsed,
            expiration - 5,
        )
        .unwrap();

    // test encoding
    // these tests will also discover if the serialized sizes change,
    //   necessitating an update to the LEN constants

    let mut profile_key_commitment_bytes =
        [0u8; zkgroup::common::constants::PROFILE_KEY_COMMITMENT_LEN];
    let mut profile_key_credential_bytes =
        [0u8; zkgroup::common::constants::EXPIRING_PROFILE_KEY_CREDENTIAL_LEN];
    let mut profile_key_credential_request_bytes =
        [0u8; zkgroup::common::constants::PROFILE_KEY_CREDENTIAL_REQUEST_LEN];
    let mut profile_key_credential_request_context_bytes =
        [0u8; zkgroup::common::constants::PROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN];
    let mut profile_key_credential_response_bytes =
        [0u8; zkgroup::common::constants::EXPIRING_PROFILE_KEY_CREDENTIAL_RESPONSE_LEN];

    profile_key_commitment_bytes
        .copy_from_slice(&bincode::serialize(&profile_key_commitment).unwrap());
    profile_key_credential_bytes
        .copy_from_slice(&bincode::serialize(&profile_key_credential).unwrap());
    profile_key_credential_request_bytes.copy_from_slice(&bincode::serialize(&request).unwrap());
    profile_key_credential_request_context_bytes
        .copy_from_slice(&bincode::serialize(&context).unwrap());
    profile_key_credential_response_bytes.copy_from_slice(&bincode::serialize(&response).unwrap());
}

#[test]
fn test_server_sigs() {
    let server_secret_params =
        zkgroup::api::server_params::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();
    let randomness = zkgroup::TEST_ARRAY_32_2;
    let message = zkgroup::TEST_ARRAY_32_1;
    let signature = server_secret_params.sign(randomness, &message);

    const EXPECTED_SIGNATURE: &[u8] = &hex!("87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06");
    assert_eq!(
        &signature[..],
        EXPECTED_SIGNATURE,
        "signature = {}",
        hex::encode(signature)
    );

    server_public_params
        .verify_signature(&message, signature)
        .unwrap();
}

#[test]
fn test_blob_encryption() {
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let randomness = zkgroup::TEST_ARRAY_32_2;

    let plaintext_vec = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19,
    ];

    // WARNING: THIS VECTOR DOES *NOT* MATCH JAVA/SWIFT/NODE AS THEY IMPLEMENT PADDING
    let ciphertext_vec = vec![
        0xe9, 0x58, 0x07, 0xb1, 0x90, 0xd4, 0x78, 0xd7, 0xbe, 0x3a, 0x77, 0xb2, 0x29, 0x27, 0x13,
        0x2e, 0xeb, 0xa5, 0x1c, 0x73, 0x9c, 0xd5, 0x70, 0x73, 0x17, 0xf7, 0x3e, 0x59, 0x1a, 0x91,
        0x5f, 0xff, 0x1f, 0x20, 0xa3, 0x02, 0x69, 0x2a, 0xfd, 0xc7, 0x08, 0x7f, 0x10, 0x19, 0x60,
        0x00,
    ];

    let calc_ciphertext_vec = group_secret_params.encrypt_blob(randomness, &plaintext_vec);
    let calc_plaintext_vec = group_secret_params
        .decrypt_blob(&calc_ciphertext_vec)
        .unwrap();
    assert_hex_eq!(calc_plaintext_vec, plaintext_vec);
    assert_hex_eq!(calc_ciphertext_vec, ciphertext_vec);
}
