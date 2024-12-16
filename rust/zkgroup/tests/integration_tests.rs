//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek_signal::ristretto::RistrettoPoint;
use hex_literal::hex;
use sha2::Sha256;
use zkgroup::{Timestamp, SECONDS_PER_DAY};

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

const AUTH_CREDENTIAL_PRESENTATION_V4_RESULT: &[u8] = &hex!("035e3e79afda8dc0d489fcf7c78f71e1502f2e06e8aeb20149046f85b3004d3f7f982d57dfad49cd1e6c335755cef4cc5e8d3de1eb4f5e8f24d71cf9f2220ae750f47181d71aaabbd48a1916813ec08eea935eb013395bf72f9139da8ef4f9530d05000000000000007a080544e6ee8ee2ff0dc298f18841103a9f9ec38631df8682e241755f86f74e26301872f4f32a9bb80f5b17651c0c83253a8013532384061a1febf79e58e60fa215b31da678305fa2a271655e35824630d0804680ec0bf29b1c775652683c3a5cec537c3514df730f267371d909f29cc6252af30afe3ea846c0cf56478bdc5b7a7f983ea7c24ecef4b371286a6414b2c38a57a7f59a9df33e430736c1a2ca14e00000000000000015416082ff7e3a741a4c3c31be3c95d4a31f2cf742685e0b17cd7f7205230e0e4e67b4b6ed45e705de13a1cb7170897bb32c9db6f9a1108fddfc7fae9eb2ca0c5fc3d8ccbd79d992eeed333626a1f0c37f0b25625955611e5ba33c782c50550045923582280cd93c3e9555b4e36eec20993f60b6aeb9ddb7f2856c4659546f037b33534a0292c77a501a70796f24ff37c8311bdfea8bb6c78f909563fe6e3b0386f36adc92090694ebb106a837bac046ad26e2472ee16408e9fd84269fd78c00c5dde91fcf202a6afad3441b9e2a34f4831d5bf560c81b38d951cb7c88e4d701765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f525474de749a0fef17b06bbce74ca5d0f7a0c45f443a1901f1e3e016d3548e50a2fa19ce6b27ac467ed9c9f5018b2a4456b6c2b1a91454422fdd473c9636a8459e1c170060c77b02000000");

const PROFILE_KEY_CREDENTIAL_PRESENTATION_V1: &[u8] = &hex!("00c4d19bca1ae844585168869da4133e0e0bb59f2ce17b7ac65bff5da9610eca103429d8022a94bae2b5b1057b5595b8ad70bfc2d0e1ad662cb75e6bae0782be6f00e3db793bc28561f0196c2e74da6f303fa8bcb70c94096671b73f7b3a95fb002200d5b9180fa0ef7d3014d01344145b4d38480d72ff25c24294e305e5705072e0d32cc4e84f5caf31486089a4b934c80c92eba43472ff23a5af93c397535d33801f0e6fc6eb2ee0d117f03bb4fd38a8b9c88d94708131f38742ca804a3cfc4f9476bc2d03f53d17001c36478afbe9cc535a224b2df6b2b08bef06cbc7d4dc42ccfc3459f7ac5c4419ae9f3c8a161d554d047778943216240858da3b1101984c40010000000000007a01eea6b2adad14d71ab8b8e411bef3c596e954b70e4031570cb1abd7e932083241f1caca3116708fa4319fbbdfe351376c23644ae09a42f0155db4996c9d0c7ffc8521c1914c0e1a20ae51e65df64dd5e6e5985b3d9d31732046d2d77f9c08aaccf056b84026073976eec6164cbdaee5d9e76e497f0c290af681cabd5c5101282abb26c3680d6087ce053310fe8a94f59d8ae23caac5fc0ed0c379888abf028a6f29f89d4fe2acc1706341b2245ba1885bca57e1e27ccf7ed79371500965009f960c2ba00fad3e93383b87ce119cac0b3360eb99284ce78e2cbed680f7960373e0ab75c190254160c2353614109489e653c9b2e1c93f92c7c5ad583d987a04bd3541b24485c33ea49bac43c87c4ab3efde2e2d7ec10a40be544199f925b20b2c55542bc56410571e41cd8e0286f609a66768b5061ccb4777af32309928dd09765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746");

const PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_RESULT: [u8; zkgroup::PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_LEN] = hex!("01e0f49cef4f25c31d1bfdc4a328fd508d2222b6decee2a253cf71e8821e97cc3f86824f79b1884b43c67f854717b1a47f56c8ff50a1c07fddbf4f6e857027d548583b54079dd61d54cdd39cd4acae5f8b3bbfa2bb6b3502b69b36da77addddc145ef254a16f2baec1e3d7e8dc80730bc608fcd0e4d8cfef3330a496380c7ac648686b9c5b914d0a77ee84848aa970b2404450179b4022eef003387f6bdbcba30344cadfd5e3f1677caa2c785f4fefe042a1b2adf4f4b8fa6023e41d704bda901d3a697904770ac46e0e304cf19f91ce9ab0ed1ccad8a6febd72313455f139b9222e9a30a2265c6cd22ee5b907fc95967417a0d8ca338a5ee4d51bba78039c314e4001000000000000749d54772b8137e570157c068a5cfebb464b6c1133c72d9abfda72db421cd00561ac4eecb94313c6912013e32c322ea36743b01814fe919ca84b9aea9c78b10ba021506f7ad8c6625e87e07ce32b559036af6b67e2c0383a643cb93cdc2b9800e90588a18fcc449cd466c28c6db73507d8282dd00808b5927fee3336ed0a2202dfb1e176fece6a4104caa2a866c475209967638ea2f1466847da7301a77b9007dfb332a30e9bbfae8a8398165ec9dd4778214e0d6ed35a34071bdf3b3b19510ff2a617bc53eb0e6b0ddc501db027bb47e4f4127d7a0104945f3d3dc7ec1741038b9b80e2c7f131c519ee26ffcb7cb9d3556cd35a12bef1d4b376fc513197ba00ce8f012a0b374164222ba79a39e74e150813474ca6f87ba705c0f06e7b7068039c5edd9dd1a5ab6793ac211989907686b45650221187d4d59ae492679f3b4308765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a746");

const PROFILE_KEY_CREDENTIAL_PRESENTATION_V3_RESULT: &[u8] = &hex!("02fc58a4f2c9bd736238abfc28890c8b2363d084bee430692f05ee559bd37dea3378949e72b271fe0d815b6d908035106cd670b45892df40780c62c37fae106c41be38371fe042a4d4f697db112972d79204b3d48d1253d3231c22926e107f661d40897cb7fdb4777c1680a57008655db71efaac1f69cd9ddf8cda33b226662d7ba443416281508fcdbb026d63f83168470a83e12803a6d2ee2c907343f2f6b063fe6bf0f17a032fabe61e77e904dfe7d3042125728c1984c86a094a0e3991ba554c1ebf604c14a8b13c384c5c01909656c114b24f9d3615d3b14bde7ce9cf126aca3e073e804b2016f7c5affa158a3a68ed9024c6880ecb441a346e7e91aedd6240010000000000002e70f27fb3f4c58cb40dfe58ce1d122312969426abb0bbb820bfbc5ff61d400a419d5ddb7c30c546427273d4fca3096ee4dd2fd03ccbbd26304ffcfe54fef50db8538177ebc61117a222253b4d4189f795abbde3b3d8a0a72d97b7750e0394010a01b474c3e942ef1ee807e17421689c6ca793c4f30b09c989b8a9679aee130eb034f64a34dbcaf12616970d2c8d58ca715bf5c4d42475fa6a1b82ba31574e072506652253e86cd783e30e1c06d2e861ba864a5373759472b31c5b26a8e46d062b8b5da2ec0a3ba499648e80f307728b7815aa60d167a0a9d01c2d2cbfb0a60ddc9dfc5343564b5f021fd1adba6d2a389e7c331bfffeed2a5d1887634323840574e49255a62d9e00ffc21f56afbb12fb9660e185f979223ec714c01e403a3a0a3276d0ef78182f12c092f5237befe3f0afea7693370788f854ec697e44c9bd02765de9df4cfa5487f360e29e99343e91811baec331c4680985e608ca5d408e21725c6aa1b61d5a8b48d75f4aaa9a3cbe88d3e0f1a54319081f77c72c8f52547448c03ab4afbf6b8fb0e126c037a0ad4094600dd0e0634d76f88c21087f3cfb485a89bc1e3abc4c95041d1d170eccf02933ec5393d4be1dc573f83c33d3b9a7468069160000000000");

#[test]
fn test_auth_credential_presentation_v1_is_rejected() {
    assert!(
        zkgroup::auth::AnyAuthCredentialPresentation::new(AUTH_CREDENTIAL_PRESENTATION_V1).is_err()
    );
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
    let redemption_time = zkgroup::Timestamp::from_epoch_seconds(123456 * SECONDS_PER_DAY);

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
        presentation_any.get_pni_ciphertext() == group_secret_params.encrypt_service_id(pni.into())
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
            redemption_time.sub_seconds(SECONDS_PER_DAY + 1),
        )
        .expect_err("credential not valid before redemption time (allowing for clock skew)");

    server_secret_params
        .verify_auth_credential_presentation(
            group_public_params,
            &presentation_any,
            redemption_time.add_seconds(2 * SECONDS_PER_DAY + 2),
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
    let expiration = zkgroup::Timestamp::from_epoch_seconds(17u64 * 24 * 60 * 60);
    let current_time = expiration.sub_seconds(2 * 24 * 60 * 60);
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
            expiration.sub_seconds(5),
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
            expiration.add_seconds(5),
        )
        .is_err());

    let presentation_parsed =
        zkgroup::profiles::AnyProfileKeyCredentialPresentation::new(presentation_bytes).unwrap();
    server_secret_params
        .verify_profile_key_credential_presentation(
            group_public_params,
            &presentation_parsed,
            expiration.sub_seconds(5),
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

/// Check that older clients can still retrieve the UUID and profile key ciphertexts from a v2
/// presentation.
///
/// This only matters for ProfileKeyCredentialPresentations; other presentation kinds are only
/// presented to the server.
#[test]
fn test_profile_key_credential_presentation_v2_as_v1() {
    let v2 = zkgroup::profiles::AnyProfileKeyCredentialPresentation::new(
        &PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_RESULT,
    )
    .unwrap();
    let v2_as_v1 = bincode::deserialize::<zkgroup::profiles::ProfileKeyCredentialPresentationV1>(
        &PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_RESULT,
    )
    .unwrap();
    assert!(v2.get_uuid_ciphertext() == v2_as_v1.get_uuid_ciphertext());
    assert!(v2.get_profile_key_ciphertext() == v2_as_v1.get_profile_key_ciphertext());
}

/// Check that an expiring presentation can be converted to a v1 presentation, at least structurally.
#[test]
fn test_profile_key_credential_presentation_expiring_as_v1() {
    let presentation = zkgroup::profiles::AnyProfileKeyCredentialPresentation::new(
        PROFILE_KEY_CREDENTIAL_PRESENTATION_V3_RESULT,
    )
    .unwrap();
    let presentation_as_v1_bytes = presentation.to_structurally_valid_v1_presentation_bytes();
    let presentation_as_v1 = bincode::deserialize::<
        zkgroup::profiles::ProfileKeyCredentialPresentationV1,
    >(&presentation_as_v1_bytes)
    .unwrap();
    assert!(presentation.get_uuid_ciphertext() == presentation_as_v1.get_uuid_ciphertext());
    assert!(
        presentation.get_profile_key_ciphertext()
            == presentation_as_v1.get_profile_key_ciphertext()
    );
}

#[test]
fn test_profile_key_credential_presentation_v1_does_not_verify() {
    // Originally from test_integration_profile.
    // SERVER
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);

    // CLIENT
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params =
        zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
    let group_public_params = group_secret_params.get_public_params();

    let redemption_time = Timestamp::from_epoch_seconds(123456 * SECONDS_PER_DAY);

    let presentation = zkgroup::profiles::AnyProfileKeyCredentialPresentation::new(
        PROFILE_KEY_CREDENTIAL_PRESENTATION_V1,
    )
    .unwrap();
    assert!(server_secret_params
        .verify_profile_key_credential_presentation(
            group_public_params,
            &presentation,
            redemption_time.add_seconds(60)
        )
        .is_err());
}
