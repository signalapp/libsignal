//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use http::{HeaderMap, Method};
use libsignal_core::{DeviceId, ServiceId, curve};
use libsignal_net::chat::Request;
use libsignal_net::infra::AsHttpHeader as _;
use libsignal_protocol::kem::PublicKey as KemPublicKey;
use libsignal_protocol::{IdentityKey, PreKeyBundle, PreKeyId, SignedPreKeyId};
use serde::{Deserialize, Deserializer};
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Padded;
use serde_with::{DeserializeAs, serde_as};

use super::{CustomError, OverWs, TryIntoResponse, WsConnection};
use crate::api::keys::{DeviceSpecifier, GetPreKeysFailure};
use crate::api::{RequestError, Unauth, UserBasedAuthorization};
use crate::logging::Redact;

type Base64Bytes = Base64<Standard, Padded>;

fn deserialize_identity_key<'de, D>(deserializer: D) -> Result<IdentityKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Base64Bytes::deserialize_as(deserializer)?;
    IdentityKey::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
}

fn deserialize_ec_public_key<'de, D>(deserializer: D) -> Result<curve::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Base64Bytes::deserialize_as(deserializer)?;
    curve::PublicKey::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
}

fn deserialize_kem_public_key<'de, D>(deserializer: D) -> Result<KemPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Base64Bytes::deserialize_as(deserializer)?;
    KemPublicKey::deserialize(bytes.as_slice()).map_err(serde::de::Error::custom)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreKeyResponse {
    #[serde(deserialize_with = "deserialize_identity_key")]
    identity_key: IdentityKey,
    devices: Vec<DeviceEntry>,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceEntry {
    device_id: u32,
    registration_id: u32,
    signed_pre_key: SignedPreKey,
    #[serde(default)]
    pre_key: Option<PreKey>,
    pq_pre_key: KyberPreKey,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedPreKey {
    key_id: u32,
    #[serde(deserialize_with = "deserialize_ec_public_key")]
    public_key: curve::PublicKey,
    #[serde_as(as = "Base64Bytes")]
    signature: Vec<u8>,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreKey {
    key_id: u32,
    #[serde(deserialize_with = "deserialize_ec_public_key")]
    public_key: curve::PublicKey,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KyberPreKey {
    key_id: u32,
    #[serde(deserialize_with = "deserialize_kem_public_key")]
    public_key: KemPublicKey,
    #[serde_as(as = "Base64Bytes")]
    signature: Vec<u8>,
}

#[async_trait]
impl<T: WsConnection> crate::api::keys::UnauthenticatedChatApi<OverWs> for Unauth<T> {
    async fn get_pre_keys(
        &self,
        auth: UserBasedAuthorization,
        target: ServiceId,
        device: DeviceSpecifier,
    ) -> Result<(IdentityKey, Vec<PreKeyBundle>), RequestError<GetPreKeysFailure>> {
        let device_specifier = device_specifier_string(device);
        let log_safe_path = format!("/v2/keys/{}/{}", Redact(&target), device_specifier);
        let request_path = format!(
            "/v2/keys/{}/{}",
            target.service_id_string(),
            device_specifier
        );

        let response = self
            .send(
                "unauth",
                &log_safe_path,
                Request {
                    method: Method::GET,
                    path: request_path.parse().expect("valid"),
                    headers: HeaderMap::from_iter([auth.as_header()]),
                    body: None,
                },
            )
            .await?;

        let raw = response.try_into_response().map_err(|e| {
            e.into_request_error(Self::ALLOW_RATE_LIMIT_CHALLENGES, |res| {
                match res.status.as_u16() {
                    401 => CustomError::Err(GetPreKeysFailure::Unauthorized),
                    404 => CustomError::Err(GetPreKeysFailure::NotFound),
                    _ => CustomError::NoCustomHandling,
                }
            })
        })?;

        parse_pre_keys_response(raw)
    }
}

fn device_specifier_string(device: DeviceSpecifier) -> String {
    match device {
        DeviceSpecifier::AllDevices => "*".to_owned(),
        DeviceSpecifier::Specific(id) => u32::from(id).to_string(),
    }
}

fn parse_pre_keys_response(
    raw: PreKeyResponse,
) -> Result<(IdentityKey, Vec<PreKeyBundle>), RequestError<GetPreKeysFailure>> {
    let PreKeyResponse {
        identity_key,
        devices,
    } = raw;

    let bundles = devices
        .into_iter()
        .map(|device| build_bundle(&identity_key, device))
        .collect::<Result<Vec<_>, _>>()?;

    Ok((identity_key, bundles))
}

fn build_bundle(
    identity_key: &IdentityKey,
    device: DeviceEntry,
) -> Result<PreKeyBundle, RequestError<GetPreKeysFailure>> {
    let device_id = DeviceId::try_from(device.device_id).map_err(|_| RequestError::Unexpected {
        log_safe: "invalid deviceId".to_owned(),
    })?;

    let pre_key = device
        .pre_key
        .map(|pre| (PreKeyId::from(pre.key_id), pre.public_key));

    PreKeyBundle::new(
        device.registration_id,
        device_id,
        pre_key,
        SignedPreKeyId::from(device.signed_pre_key.key_id),
        device.signed_pre_key.public_key,
        device.signed_pre_key.signature,
        device.pq_pre_key.key_id.into(),
        device.pq_pre_key.public_key,
        device.pq_pre_key.signature,
        *identity_key,
    )
    .map_err(|_| RequestError::Unexpected {
        log_safe: "invalid pre-key bundle content".to_owned(),
    })
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use futures_util::FutureExt as _;
    use http::{HeaderValue, Method};
    use libsignal_core::{DeviceId, ServiceId, curve};
    use libsignal_net::chat::Request;
    use libsignal_protocol::KyberPreKeyId;
    use libsignal_protocol::kem::PublicKey as KemPublicKey;

    use super::*;
    use crate::api::UserBasedAuthorization;
    use crate::api::keys::{DeviceSpecifier, UnauthenticatedChatApi};
    use crate::ws::ACCESS_KEY_HEADER_NAME;
    use crate::ws::testutil::{
        ProduceResponse, RequestValidator, empty, headers, json as response_json,
    };

    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const DEVICE_ID: u32 = 2;
    const REGISTRATION_ID: u32 = 1234;
    const PRE_KEY_ID: u32 = 5;
    const SIGNED_PRE_KEY_ID: u32 = 7;
    const KYBER_PRE_KEY_ID: u32 = 9;
    const SECOND_DEVICE_ID: u32 = 3;
    const SECOND_REGISTRATION_ID: u32 = 5678;
    const SECOND_PRE_KEY_ID: u32 = 11;
    const SECOND_SIGNED_PRE_KEY_ID: u32 = 13;
    const SECOND_KYBER_PRE_KEY_ID: u32 = 15;
    const TEST_ACCESS_KEY: [u8; 16] = [0x11; 16];

    #[test]
    fn test_success_with_all_keys() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0xAA);
        let signed_pre_key_public = dummy_ec_public_key(0xBB);
        let signed_pre_key_signature = vec![0xCC; 64];
        let pre_key_public = dummy_ec_public_key(0xDD);
        let kyber_pre_key_public = dummy_kem_public_key(0xEE);
        let kyber_pre_key_signature = vec![0xFF; 64];

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [{
                "deviceId": DEVICE_ID,
                "registrationId": REGISTRATION_ID,
                "signedPreKey": {
                    "keyId": SIGNED_PRE_KEY_ID,
                    "publicKey": base64(&signed_pre_key_public.serialize()),
                    "signature": base64(&signed_pre_key_signature),
                },
                "preKey": {
                    "keyId": PRE_KEY_ID,
                    "publicKey": base64(&pre_key_public.serialize()),
                },
                "pqPreKey": {
                    "keyId": KYBER_PRE_KEY_ID,
                    "publicKey": base64(&kyber_pre_key_public.serialize()),
                    "signature": base64(&kyber_pre_key_signature),
                }
            }]
        });

        let expected_headers = http::HeaderMap::from_iter([(
            ACCESS_KEY_HEADER_NAME,
            HeaderValue::from_str(&BASE64_STANDARD.encode(TEST_ACCESS_KEY)).expect("header value"),
        )]);

        let expected_request = Request {
            method: Method::GET,
            path: format!("/v2/keys/{ACI_UUID}/{DEVICE_ID}")
                .parse()
                .expect("valid path"),
            headers: expected_headers,
            body: None,
        };

        let validator = RequestValidator {
            expected: expected_request,
            response: response_json(200, payload.to_string()),
        };

        let (response_identity_key, bundles) = Unauth(validator)
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready")
            .expect("success");

        assert_eq!(response_identity_key, identity_key);
        assert_eq!(bundles.len(), 1);
        let bundle = &bundles[0];
        assert_eq!(bundle.registration_id().unwrap(), REGISTRATION_ID);
        assert_eq!(bundle.device_id().unwrap(), device_id);
        assert_eq!(
            bundle.pre_key_id().unwrap().unwrap(),
            PreKeyId::from(PRE_KEY_ID)
        );
        assert_eq!(bundle.pre_key_public().unwrap().unwrap(), pre_key_public);
        assert_eq!(
            bundle.signed_pre_key_id().unwrap(),
            SignedPreKeyId::from(SIGNED_PRE_KEY_ID)
        );
        assert_eq!(
            bundle.signed_pre_key_public().unwrap(),
            signed_pre_key_public
        );
        assert_eq!(
            bundle.signed_pre_key_signature().unwrap(),
            signed_pre_key_signature.as_slice()
        );
        assert_eq!(
            bundle.kyber_pre_key_id().unwrap(),
            KyberPreKeyId::from(KYBER_PRE_KEY_ID)
        );
        assert_eq!(
            bundle.kyber_pre_key_public().unwrap(),
            &kyber_pre_key_public
        );
        assert_eq!(
            bundle.kyber_pre_key_signature().unwrap(),
            kyber_pre_key_signature.as_slice()
        );
    }

    #[test]
    fn test_success_all_devices() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let first_device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");
        let second_device_id = DeviceId::try_from(SECOND_DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0xA1);

        let first_signed_pre_key_public = dummy_ec_public_key(0xB2);
        let first_signed_pre_key_signature = vec![0xC3; 64];
        let first_pre_key_public = dummy_ec_public_key(0xD4);
        let first_kyber_pre_key_public = dummy_kem_public_key(0xE5);
        let first_kyber_pre_key_signature = vec![0xF6; 64];

        let second_signed_pre_key_public = dummy_ec_public_key(0x21);
        let second_signed_pre_key_signature = vec![0x32; 64];
        let second_pre_key_public = dummy_ec_public_key(0x43);
        let second_kyber_pre_key_public = dummy_kem_public_key(0x54);
        let second_kyber_pre_key_signature = vec![0x65; 64];

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [
                {
                    "deviceId": DEVICE_ID,
                    "registrationId": REGISTRATION_ID,
                    "signedPreKey": {
                        "keyId": SIGNED_PRE_KEY_ID,
                        "publicKey": base64(&first_signed_pre_key_public.serialize()),
                        "signature": base64(&first_signed_pre_key_signature),
                    },
                    "preKey": {
                        "keyId": PRE_KEY_ID,
                        "publicKey": base64(&first_pre_key_public.serialize()),
                    },
                    "pqPreKey": {
                        "keyId": KYBER_PRE_KEY_ID,
                        "publicKey": base64(&first_kyber_pre_key_public.serialize()),
                        "signature": base64(&first_kyber_pre_key_signature),
                    }
                },
                {
                    "deviceId": SECOND_DEVICE_ID,
                    "registrationId": SECOND_REGISTRATION_ID,
                    "signedPreKey": {
                        "keyId": SECOND_SIGNED_PRE_KEY_ID,
                        "publicKey": base64(&second_signed_pre_key_public.serialize()),
                        "signature": base64(&second_signed_pre_key_signature),
                    },
                    "preKey": {
                        "keyId": SECOND_PRE_KEY_ID,
                        "publicKey": base64(&second_pre_key_public.serialize()),
                    },
                    "pqPreKey": {
                        "keyId": SECOND_KYBER_PRE_KEY_ID,
                        "publicKey": base64(&second_kyber_pre_key_public.serialize()),
                        "signature": base64(&second_kyber_pre_key_signature),
                    }
                }
            ]
        });

        let validator = RequestValidator {
            expected: Request {
                method: Method::GET,
                path: format!("/v2/keys/{ACI_UUID}/*")
                    .parse()
                    .expect("valid path"),
                headers: http::HeaderMap::from_iter([(
                    ACCESS_KEY_HEADER_NAME,
                    HeaderValue::from_str(&BASE64_STANDARD.encode(TEST_ACCESS_KEY))
                        .expect("header value"),
                )]),
                body: None,
            },
            response: response_json(200, payload.to_string()),
        };

        let (response_identity_key, bundles) = Unauth(validator)
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::AllDevices,
            )
            .now_or_never()
            .expect("future ready")
            .expect("success");

        assert_eq!(response_identity_key, identity_key);
        assert_eq!(bundles.len(), 2);

        let mut bundles_by_device = HashMap::new();
        for bundle in bundles {
            let device_id = bundle.device_id().expect("device id");
            assert!(bundles_by_device.insert(device_id, bundle).is_none());
        }

        let first_bundle = bundles_by_device
            .remove(&first_device_id)
            .expect("bundle for first device");
        assert_eq!(first_bundle.registration_id().unwrap(), REGISTRATION_ID);
        assert_eq!(first_bundle.device_id().unwrap(), first_device_id);
        assert_eq!(
            first_bundle.pre_key_id().unwrap().unwrap(),
            PreKeyId::from(PRE_KEY_ID)
        );
        assert_eq!(
            first_bundle.pre_key_public().unwrap().unwrap(),
            first_pre_key_public
        );
        assert_eq!(
            first_bundle.signed_pre_key_id().unwrap(),
            SignedPreKeyId::from(SIGNED_PRE_KEY_ID)
        );
        assert_eq!(
            first_bundle.signed_pre_key_public().unwrap(),
            first_signed_pre_key_public
        );
        assert_eq!(
            first_bundle.signed_pre_key_signature().unwrap(),
            first_signed_pre_key_signature.as_slice()
        );
        assert_eq!(
            first_bundle.kyber_pre_key_id().unwrap(),
            KyberPreKeyId::from(KYBER_PRE_KEY_ID)
        );
        assert_eq!(
            first_bundle.kyber_pre_key_public().unwrap(),
            &first_kyber_pre_key_public
        );
        assert_eq!(
            first_bundle.kyber_pre_key_signature().unwrap(),
            first_kyber_pre_key_signature.as_slice()
        );

        let second_bundle = bundles_by_device
            .remove(&second_device_id)
            .expect("bundle for second device");
        assert_eq!(
            second_bundle.registration_id().unwrap(),
            SECOND_REGISTRATION_ID
        );
        assert_eq!(second_bundle.device_id().unwrap(), second_device_id);
        assert_eq!(
            second_bundle.pre_key_id().unwrap().unwrap(),
            PreKeyId::from(SECOND_PRE_KEY_ID)
        );
        assert_eq!(
            second_bundle.pre_key_public().unwrap().unwrap(),
            second_pre_key_public
        );
        assert_eq!(
            second_bundle.signed_pre_key_id().unwrap(),
            SignedPreKeyId::from(SECOND_SIGNED_PRE_KEY_ID)
        );
        assert_eq!(
            second_bundle.signed_pre_key_public().unwrap(),
            second_signed_pre_key_public
        );
        assert_eq!(
            second_bundle.signed_pre_key_signature().unwrap(),
            second_signed_pre_key_signature.as_slice()
        );
        assert_eq!(
            second_bundle.kyber_pre_key_id().unwrap(),
            KyberPreKeyId::from(SECOND_KYBER_PRE_KEY_ID)
        );
        assert_eq!(
            second_bundle.kyber_pre_key_public().unwrap(),
            &second_kyber_pre_key_public
        );
        assert_eq!(
            second_bundle.kyber_pre_key_signature().unwrap(),
            second_kyber_pre_key_signature.as_slice()
        );

        assert!(bundles_by_device.is_empty());
    }

    #[test]
    fn test_success_without_one_time_pre_key() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0x12);
        let signed_pre_key_public = dummy_ec_public_key(0x34);
        let signed_pre_key_signature = vec![0x56; 64];
        let kyber_pre_key_public = dummy_kem_public_key(0x78);
        let kyber_pre_key_signature = vec![0x9A; 64];

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [{
                "deviceId": DEVICE_ID,
                "registrationId": REGISTRATION_ID,
                "signedPreKey": {
                    "keyId": SIGNED_PRE_KEY_ID,
                    "publicKey": base64(&signed_pre_key_public.serialize()),
                    "signature": base64(&signed_pre_key_signature),
                },
                "pqPreKey": {
                    "keyId": KYBER_PRE_KEY_ID,
                    "publicKey": base64(&kyber_pre_key_public.serialize()),
                    "signature": base64(&kyber_pre_key_signature),
                }
            }]
        });

        let validator = RequestValidator {
            expected: Request {
                method: Method::GET,
                path: format!("/v2/keys/{ACI_UUID}/{DEVICE_ID}")
                    .parse()
                    .expect("valid path"),
                headers: http::HeaderMap::from_iter([(
                    ACCESS_KEY_HEADER_NAME,
                    HeaderValue::from_str(&BASE64_STANDARD.encode(TEST_ACCESS_KEY))
                        .expect("header value"),
                )]),
                body: None,
            },
            response: response_json(200, payload.to_string()),
        };

        let (response_identity_key, bundles) = Unauth(validator)
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready")
            .expect("success");

        assert_eq!(response_identity_key, identity_key);
        assert_eq!(bundles.len(), 1);
        let bundle = &bundles[0];
        assert!(bundle.pre_key_id().unwrap().is_none());
        assert!(bundle.pre_key_public().unwrap().is_none());
        assert_eq!(
            bundle.signed_pre_key_public().unwrap(),
            signed_pre_key_public
        );
        assert_eq!(
            bundle.kyber_pre_key_public().unwrap(),
            &kyber_pre_key_public
        );
    }

    #[test]
    fn test_unauthorized_error() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let result = Unauth(ProduceResponse(empty(401)))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(
            result,
            Err(RequestError::Other(GetPreKeysFailure::Unauthorized))
        ));
    }

    #[test]
    fn test_not_found_error() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let result = Unauth(ProduceResponse(empty(404)))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(
            result,
            Err(RequestError::Other(GetPreKeysFailure::NotFound))
        ));
    }

    #[test]
    fn test_retry_later_error() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let response = headers(429, &[(http::header::RETRY_AFTER, "60")]);

        let result = Unauth(ProduceResponse(response))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(result, Err(RequestError::RetryLater(_))));
    }

    #[test]
    fn test_malformed_identity_key() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let payload = serde_json::json!({
            "identityKey": base64(&[0x00, 0x01, 0x02]),
            "devices": []
        });

        let result = Unauth(ProduceResponse(response_json(200, payload.to_string())))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(result, Err(RequestError::Unexpected { .. })));
    }

    #[test]
    fn test_invalid_device_id() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0x10);
        let signed_pre_key_public = dummy_ec_public_key(0x11);
        let signed_pre_key_signature = vec![0x12; 64];
        let pre_key_public = dummy_ec_public_key(0x13);
        let kyber_pre_key_public = dummy_kem_public_key(0x14);
        let kyber_pre_key_signature = vec![0x15; 64];

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [{
                "deviceId": 0,
                "registrationId": REGISTRATION_ID,
                "signedPreKey": {
                    "keyId": SIGNED_PRE_KEY_ID,
                    "publicKey": base64(&signed_pre_key_public.serialize()),
                    "signature": base64(&signed_pre_key_signature),
                },
                "preKey": {
                    "keyId": PRE_KEY_ID,
                    "publicKey": base64(&pre_key_public.serialize()),
                },
                "pqPreKey": {
                    "keyId": KYBER_PRE_KEY_ID,
                    "publicKey": base64(&kyber_pre_key_public.serialize()),
                    "signature": base64(&kyber_pre_key_signature),
                }
            }]
        });

        let result = Unauth(ProduceResponse(response_json(200, payload.to_string())))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(result, Err(RequestError::Unexpected { .. })));
    }

    #[test]
    fn test_missing_signed_pre_key() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0x20);
        let pre_key_public = dummy_ec_public_key(0x21);
        let kyber_pre_key_public = dummy_kem_public_key(0x22);
        let kyber_pre_key_signature = vec![0x23; 64];

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [{
                "deviceId": DEVICE_ID,
                "registrationId": REGISTRATION_ID,
                "preKey": {
                    "keyId": PRE_KEY_ID,
                    "publicKey": base64(&pre_key_public.serialize()),
                },
                "pqPreKey": {
                    "keyId": KYBER_PRE_KEY_ID,
                    "publicKey": base64(&kyber_pre_key_public.serialize()),
                    "signature": base64(&kyber_pre_key_signature),
                }
            }]
        });

        let result = Unauth(ProduceResponse(response_json(200, payload.to_string())))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(result, Err(RequestError::Unexpected { .. })));
    }

    #[test]
    fn test_missing_pq_pre_key() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0x30);
        let signed_pre_key_public = dummy_ec_public_key(0x31);
        let signed_pre_key_signature = vec![0x32; 64];
        let pre_key_public = dummy_ec_public_key(0x33);

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [{
                "deviceId": DEVICE_ID,
                "registrationId": REGISTRATION_ID,
                "signedPreKey": {
                    "keyId": SIGNED_PRE_KEY_ID,
                    "publicKey": base64(&signed_pre_key_public.serialize()),
                    "signature": base64(&signed_pre_key_signature),
                },
                "preKey": {
                    "keyId": PRE_KEY_ID,
                    "publicKey": base64(&pre_key_public.serialize()),
                }
            }]
        });

        let result = Unauth(ProduceResponse(response_json(200, payload.to_string())))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(result, Err(RequestError::Unexpected { .. })));
    }

    #[test]
    fn test_invalid_signed_pre_key_public_key() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0x40);
        let signed_pre_key_signature = vec![0x41; 64];
        let pre_key_public = dummy_ec_public_key(0x42);
        let kyber_pre_key_public = dummy_kem_public_key(0x43);
        let kyber_pre_key_signature = vec![0x44; 64];

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [{
                "deviceId": DEVICE_ID,
                "registrationId": REGISTRATION_ID,
                "signedPreKey": {
                    "keyId": SIGNED_PRE_KEY_ID,
                    "publicKey": base64(&[0x00]),
                    "signature": base64(&signed_pre_key_signature),
                },
                "preKey": {
                    "keyId": PRE_KEY_ID,
                    "publicKey": base64(&pre_key_public.serialize()),
                },
                "pqPreKey": {
                    "keyId": KYBER_PRE_KEY_ID,
                    "publicKey": base64(&kyber_pre_key_public.serialize()),
                    "signature": base64(&kyber_pre_key_signature),
                }
            }]
        });

        let result = Unauth(ProduceResponse(response_json(200, payload.to_string())))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(result, Err(RequestError::Unexpected { .. })));
    }

    #[test]
    fn test_invalid_signed_pre_key_signature_base64() {
        let service_id =
            ServiceId::parse_from_service_id_string(ACI_UUID).expect("valid service identifier");
        let device_id = DeviceId::try_from(DEVICE_ID).expect("valid device id");

        let identity_key = dummy_identity_key(0x50);
        let signed_pre_key_public = dummy_ec_public_key(0x51);
        let pre_key_public = dummy_ec_public_key(0x52);
        let kyber_pre_key_public = dummy_kem_public_key(0x53);
        let kyber_pre_key_signature = vec![0x54; 64];

        let payload = serde_json::json!({
            "identityKey": base64(&identity_key.serialize()),
            "devices": [{
                "deviceId": DEVICE_ID,
                "registrationId": REGISTRATION_ID,
                "signedPreKey": {
                    "keyId": SIGNED_PRE_KEY_ID,
                    "publicKey": base64(&signed_pre_key_public.serialize()),
                    "signature": "not_base64",
                },
                "preKey": {
                    "keyId": PRE_KEY_ID,
                    "publicKey": base64(&pre_key_public.serialize()),
                },
                "pqPreKey": {
                    "keyId": KYBER_PRE_KEY_ID,
                    "publicKey": base64(&kyber_pre_key_public.serialize()),
                    "signature": base64(&kyber_pre_key_signature),
                }
            }]
        });

        let result = Unauth(ProduceResponse(response_json(200, payload.to_string())))
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                service_id,
                DeviceSpecifier::Specific(device_id),
            )
            .now_or_never()
            .expect("future ready");

        assert!(matches!(result, Err(RequestError::Unexpected { .. })));
    }

    fn dummy_identity_key(fill: u8) -> IdentityKey {
        let bytes = dummy_ec_public_key_bytes(fill);
        IdentityKey::try_from(bytes.as_slice()).expect("valid identity key")
    }

    fn dummy_ec_public_key(fill: u8) -> curve::PublicKey {
        let bytes = dummy_ec_public_key_bytes(fill);
        curve::PublicKey::try_from(bytes.as_slice()).expect("valid EC public key")
    }

    fn dummy_kem_public_key(fill: u8) -> KemPublicKey {
        let bytes = dummy_kem_public_key_bytes(fill);
        KemPublicKey::deserialize(bytes.as_slice()).expect("valid kyber public key")
    }

    fn dummy_ec_public_key_bytes(fill: u8) -> Vec<u8> {
        let mut bytes = vec![0x05];
        bytes.extend(std::iter::repeat_n(fill, 32));
        bytes
    }

    fn dummy_kem_public_key_bytes(fill: u8) -> Vec<u8> {
        let mut bytes = vec![0x08];
        // 1568 is kyber1024::Parameters::PUBLIC_KEY_LENGTH
        bytes.extend(std::iter::repeat_n(fill, 1568));
        bytes
    }

    fn base64(bytes: &[u8]) -> String {
        BASE64_STANDARD.encode(bytes)
    }
}
