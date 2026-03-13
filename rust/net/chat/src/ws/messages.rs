//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use assert_matches::debug_assert_matches;
use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use itertools::Itertools as _;
use libsignal_core::{DeviceId, ServiceId};
use libsignal_net::chat::{Request, Response};
use libsignal_net::infra::AsHttpHeader as _;
use libsignal_net_grpc::proto::chat::services;
use serde_with::serde_as;

use super::{
    CONTENT_TYPE_JSON, CustomError, OverWs, TryIntoResponse, WsConnection, expect_empty_body,
    parse_json_from_body,
};
use crate::api::messages::{
    MismatchedDeviceError, MultiRecipientMessageResponse, MultiRecipientSendAuthorization,
    MultiRecipientSendFailure, SealedSendFailure, SingleOutboundSealedSenderMessage,
    UserBasedSendAuthorization,
};
use crate::api::{RequestError, Unauth};
use crate::logging::Redact;

const GROUP_SEND_TOKEN_HEADER: http::HeaderName = http::HeaderName::from_static("group-send-token");
const MULTI_RECIPIENT_MESSAGE_CONTENT_TYPE: http::HeaderValue =
    http::HeaderValue::from_static("application/vnd.signal-messenger.mrm");

type Base64Padded =
    serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>;

impl UserBasedSendAuthorization {
    fn to_header(&self) -> Option<(http::HeaderName, http::HeaderValue)> {
        match self {
            UserBasedSendAuthorization::Story => None,
            UserBasedSendAuthorization::User(user_based_authorization) => {
                Some(user_based_authorization.as_header())
            }
        }
    }
}

/// From SignalService.proto's Envelope.Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(into = "u8")]
#[repr(u8)]
#[allow(dead_code)]
enum EnvelopeType {
    Unknown = 0,
    DoubleRatchet = 1,
    PreKey = 3,
    ServerDeliveryReceipt = 5,
    UnidentifiedSender = 6,
    PlaintextContent = 8,
}

impl From<EnvelopeType> for u8 {
    fn from(value: EnvelopeType) -> Self {
        value as Self
    }
}

impl MultiRecipientSendAuthorization {
    fn to_header(&self) -> Option<(http::HeaderName, http::HeaderValue)> {
        match self {
            MultiRecipientSendAuthorization::Story => None,
            MultiRecipientSendAuthorization::Group(group_send_full_token) => Some((
                GROUP_SEND_TOKEN_HEADER,
                BASE64_STANDARD
                    .encode(zkgroup::serialize(group_send_full_token))
                    .parse()
                    .expect("valid"),
            )),
        }
    }
}

#[serde_as]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SingleOutboundMessageRepresentation<'a> {
    #[serde(rename = "type")]
    message_type: EnvelopeType,
    destination_device_id: u8,
    destination_registration_id: u32,
    #[serde_as(as = "Base64Padded")]
    content: &'a [u8],
}

/// Used for both authenticated and unauthenticated sends
#[derive(serde::Serialize)]
struct SendMessageRequest<'a> {
    messages: Vec<SingleOutboundMessageRepresentation<'a>>,
    online: bool,
    urgent: bool,
    timestamp: u64,
}

#[async_trait]
impl<T: WsConnection> crate::api::messages::UnauthenticatedChatApi<OverWs> for Unauth<T> {
    async fn send_message<'a>(
        &self,
        destination: ServiceId,
        timestamp: libsignal_protocol::Timestamp,
        contents: Vec<SingleOutboundSealedSenderMessage<'a>>,
        auth: UserBasedSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<(), RequestError<SealedSendFailure>> {
        let story_suffix = if matches!(auth, UserBasedSendAuthorization::Story) {
            "?story=true"
        } else {
            ""
        };
        let path = format!(
            "/v1/messages/{}{}",
            destination.service_id_string(),
            story_suffix,
        );
        let log_safe_path = format!(
            "/v1/messages/{}{} (ts: {})",
            Redact(destination),
            story_suffix,
            timestamp.epoch_millis()
        );

        let request = SendMessageRequest {
            messages: contents
                .iter()
                .map(|message| SingleOutboundMessageRepresentation {
                    message_type: EnvelopeType::UnidentifiedSender,
                    destination_device_id: message.device_id.into(),
                    destination_registration_id: message.registration_id,
                    content: &message.contents,
                })
                .collect(),
            online: online_only,
            urgent,
            timestamp: timestamp.epoch_millis(),
        };

        let response = self
            .send(
                "unauth",
                &log_safe_path,
                Request {
                    method: http::Method::PUT,
                    path: path.parse().expect("valid"),
                    headers: http::HeaderMap::from_iter(
                        [CONTENT_TYPE_JSON].into_iter().chain(auth.to_header()),
                    ),
                    body: Some(
                        serde_json::to_vec(&request)
                            .expect("can serialize request")
                            .into(),
                    ),
                },
            )
            .await?;

        // The server response includes a field we don't read.
        #[derive(serde::Deserialize)]
        struct RawSendMessageResponse {}

        let RawSendMessageResponse {} = response.try_into_response().map_err(|e| {
            e.into_request_error(Self::ALLOW_RATE_LIMIT_CHALLENGES, |response| match response
                .status
                .as_u16()
            {
                401 => {
                    expect_empty_body(response, "/v1/messages/*");
                    SealedSendFailure::Unauthorized.into()
                }
                404 => {
                    expect_empty_body(response, "/v1/messages/*");
                    SealedSendFailure::ServiceIdNotFound.into()
                }
                409 | 410 => {
                    parse_single_recipient_mismatched_devices_response(destination, response)
                }
                _ => CustomError::NoCustomHandling,
            })
        })?;

        Ok(())
    }

    async fn send_multi_recipient_message(
        &self,
        payload: bytes::Bytes,
        timestamp: libsignal_protocol::Timestamp,
        auth: MultiRecipientSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>> {
        if let Some(grpc) = self
            .grpc_service_to_use_instead(
                services::MessagesAnonymous::SendMultiRecipientMessage.into(),
            )
            .await
        {
            return Unauth(grpc)
                .send_multi_recipient_message(payload, timestamp, auth, online_only, urgent)
                .await;
        }

        let log_safe_path = format!(
            "/v1/messages/multi_recipient?ts={}&online={}&urgent={}{}",
            timestamp.epoch_millis(),
            online_only,
            urgent,
            if matches!(auth, MultiRecipientSendAuthorization::Story) {
                "&story=true"
            } else {
                ""
            }
        );
        let response = self
            .send(
                "unauth",
                &log_safe_path,
                Request {
                    method: http::Method::PUT,
                    path: log_safe_path.parse().expect("valid"),
                    headers: http::HeaderMap::from_iter(
                        [(
                            http::header::CONTENT_TYPE,
                            MULTI_RECIPIENT_MESSAGE_CONTENT_TYPE,
                        )]
                        .into_iter()
                        .chain(auth.to_header()),
                    ),
                    body: Some(payload),
                },
            )
            .await?;

        #[derive(serde::Deserialize)]
        struct RawMultiRecipientMessageResponse {
            #[serde(default)]
            uuids404: Vec<String>,
        }

        let RawMultiRecipientMessageResponse { uuids404 } =
            response.try_into_response().map_err(|e| {
                e.into_request_error(Self::ALLOW_RATE_LIMIT_CHALLENGES, |response| match response
                    .status
                    .as_u16()
                {
                    401 => {
                        expect_empty_body(response, "/v1/messages/multi_recipient");
                        MultiRecipientSendFailure::Unauthorized.into()
                    }
                    409 | 410 => parse_multi_recipient_mismatched_devices_response(response),
                    _ => CustomError::NoCustomHandling,
                })
            })?;

        Ok(MultiRecipientMessageResponse {
            unregistered_ids: uuids404
                .into_iter()
                .map(|id| {
                    ServiceId::parse_from_service_id_string(&id).ok_or_else(|| RequestError::<
                        MultiRecipientSendFailure,
                    >::Unexpected {
                        log_safe: "could not parse ServiceId in uuids404".to_owned(),
                    })
                })
                .try_collect()?,
        })
    }
}

#[derive(serde::Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ParsedMismatchedDevices {
    // 409 fields
    #[serde(default)]
    missing_devices: Vec<u8>,
    #[serde(default)]
    extra_devices: Vec<u8>,
    // 410 fields
    #[serde(default)]
    stale_devices: Vec<u8>,
}

impl ParsedMismatchedDevices {
    fn try_into_error<E>(
        self,
        account: ServiceId,
    ) -> Result<MismatchedDeviceError, CustomError<E>> {
        if self == Default::default() {
            return Err(CustomError::Unexpected {
                log_safe: "no devices listed in mismatched device response".to_owned(),
            });
        }

        fn validate_device_id<E>(
            input: u8,
            label: &'static str,
        ) -> Result<DeviceId, CustomError<E>> {
            DeviceId::new(input).map_err(|_| CustomError::Unexpected {
                log_safe: format!("invalid device ID {input} in {label} array"),
            })
        }

        let ParsedMismatchedDevices {
            missing_devices,
            extra_devices,
            stale_devices,
        } = self;

        Ok(MismatchedDeviceError {
            account,
            missing_devices: missing_devices
                .into_iter()
                .map(|id| validate_device_id(id, "missingDevices"))
                .try_collect()?,
            extra_devices: extra_devices
                .into_iter()
                .map(|id| validate_device_id(id, "extraDevices"))
                .try_collect()?,
            stale_devices: stale_devices
                .into_iter()
                .map(|id| validate_device_id(id, "staleDevices"))
                .try_collect()?,
        })
    }
}

fn parse_single_recipient_mismatched_devices_response(
    recipient: ServiceId,
    response: &Response,
) -> CustomError<SealedSendFailure> {
    debug_assert_matches!(response.status.as_u16(), 409 | 410);

    let parsed_devices: ParsedMismatchedDevices = match parse_json_from_body(response) {
        Ok(parsed) => parsed,
        Err(e) => {
            return CustomError::Unexpected {
                log_safe: e.to_string(),
            };
        }
    };

    match parsed_devices.try_into_error(recipient) {
        Ok(converted) => SealedSendFailure::MismatchedDevices(converted).into(),
        Err(e) => e,
    }
}

fn parse_multi_recipient_mismatched_devices_response(
    response: &Response,
) -> CustomError<MultiRecipientSendFailure> {
    debug_assert_matches!(response.status.as_u16(), 409 | 410);

    #[derive(serde::Deserialize)]
    struct ParsedMismatchedDevicesEntry {
        #[serde(rename = "uuid")]
        service_id: String,
        devices: ParsedMismatchedDevices,
    }

    let parsed_entries: Vec<ParsedMismatchedDevicesEntry> = match parse_json_from_body(response) {
        Ok(parsed) => parsed,
        Err(e) => {
            return CustomError::Unexpected {
                log_safe: e.to_string(),
            };
        }
    };

    let per_recipient_errors = parsed_entries
        .into_iter()
        .map(|entry| {
            let ParsedMismatchedDevicesEntry {
                service_id,
                devices,
            } = entry;
            let account =
                ServiceId::parse_from_service_id_string(&service_id).ok_or_else(|| {
                    CustomError::Unexpected {
                        log_safe: "could not parse ServiceId in mismatched device response"
                            .to_owned(),
                    }
                })?;
            devices.try_into_error(account)
        })
        .try_collect();
    match per_recipient_errors {
        Ok(errors) => MultiRecipientSendFailure::MismatchedDevices(errors).into(),
        Err(e) => e,
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use futures_util::FutureExt;
    use libsignal_core::{Aci, Pni};
    use libsignal_protocol::Timestamp;
    use test_case::test_case;
    use uuid::Uuid;

    use super::*;
    use crate::api::UserBasedAuthorization;
    use crate::api::messages::UnauthenticatedChatApi;
    use crate::api::testutil::{SERIALIZED_GROUP_SEND_TOKEN, structurally_valid_group_send_token};
    use crate::ws::ACCESS_KEY_HEADER_NAME;
    use crate::ws::testutil::{RequestValidator, compress_json, empty, json};

    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const PNI_UUID: &str = "796abedb-ca4e-4f18-8803-1fde5b921f9f";

    type MrResponse = MultiRecipientMessageResponse;
    type MrFailure = MultiRecipientSendFailure;

    #[test_case(json(200, r#"{}"#) => matches Ok(()))]
    #[test_case(json(200, r#"{"needsSync":true}"#) => matches Ok(()))]
    #[test_case(empty(200) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(empty(401) => matches Err(RequestError::Other(SealedSendFailure::Unauthorized)))]
    #[test_case(empty(404) => matches Err(RequestError::Other(SealedSendFailure::ServiceIdNotFound)))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    #[test_case(empty(409) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        409, r#"{"missingDevices":[50,60]}"#
    ) => matches Err(RequestError::Other(SealedSendFailure::MismatchedDevices(error))) if error ==
        MismatchedDeviceError {
            account: Pni::from(Uuid::try_parse(PNI_UUID).unwrap()).into(),
            missing_devices: vec![DeviceId::new(50).unwrap(), DeviceId::new(60).unwrap()],
            extra_devices: vec![],
            stale_devices: vec![],
        }
    )]
    #[test_case(json(
        409, r#"{"missingDevices":[],"extraDevices":[4,5]}"#
    ) => matches Err(RequestError::Other(SealedSendFailure::MismatchedDevices(error))) if error ==
        MismatchedDeviceError {
            account: Pni::from(Uuid::try_parse(PNI_UUID).unwrap()).into(),
            missing_devices: vec![],
            extra_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
            stale_devices: vec![],
        }
    )]
    #[test_case(json(
        410, r#"{"staleDevices":[4,5]}"#
    ) => matches Err(RequestError::Other(SealedSendFailure::MismatchedDevices(error))) if error ==
        MismatchedDeviceError {
            account: Pni::from(Uuid::try_parse(PNI_UUID).unwrap()).into(),
            missing_devices: vec![],
            extra_devices: vec![],
            stale_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
        }
    )]
    #[test_case(json(
        410, r#"["#
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        410, r#"{"staleDevices":[200]}"#
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        410, r#"{"staleDevices":["4"]}"#
    ) => matches Err(RequestError::Unexpected { .. }))]
    fn test_sealed_send(response: Response) -> Result<(), RequestError<SealedSendFailure>> {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(const_str::concat!(
                    "/v1/messages/PNI:",
                    PNI_UUID
                )),
                headers: http::HeaderMap::from_iter([
                    CONTENT_TYPE_JSON,
                    (
                        ACCESS_KEY_HEADER_NAME,
                        http::HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
                    ),
                ]),
                body: Some(
                    compress_json!(
                        r#"{
                            "messages": [
                                {
                                    "type": 6,
                                    "destinationDeviceId": 2,
                                    "destinationRegistrationId": 22,
                                    "content": "//8="
                                },
                                {
                                    "type": 6,
                                    "destinationDeviceId": 3,
                                    "destinationRegistrationId": 33,
                                    "content": "/v4="
                                }
                            ],
                            "online": false,
                            "urgent": true,
                            "timestamp": 1700000000000
                        }"#
                    )
                    .into(),
                ),
            },
            response,
        };

        Unauth(validator)
            .send_message(
                Pni::from(uuid::Uuid::try_parse(PNI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                vec![
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[0xff, 0xff]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[0xfe, 0xfe]),
                    },
                ],
                UserBasedSendAuthorization::User(UserBasedAuthorization::AccessKey([0; 16])),
                false,
                true,
            )
            .now_or_never()
            .expect("sync")
    }

    #[test]
    fn test_sealed_send_using_group_token() {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(const_str::concat!(
                    "/v1/messages/",
                    ACI_UUID,
                )),
                headers: http::HeaderMap::from_iter([
                    CONTENT_TYPE_JSON,
                    (
                        GROUP_SEND_TOKEN_HEADER,
                        http::HeaderValue::from_maybe_shared(
                            BASE64_STANDARD.encode(SERIALIZED_GROUP_SEND_TOKEN),
                        )
                        .expect("valid"),
                    ),
                ]),
                body: Some(
                    compress_json!(
                        r#"{
                            "messages": [
                                {
                                    "type": 6,
                                    "destinationDeviceId": 2,
                                    "destinationRegistrationId": 22,
                                    "content": "//8="
                                },
                                {
                                    "type": 6,
                                    "destinationDeviceId": 3,
                                    "destinationRegistrationId": 33,
                                    "content": "/v4="
                                }
                            ],
                            "online": true,
                            "urgent": false,
                            "timestamp": 1700000000000
                        }"#
                    )
                    .into(),
                ),
            },
            response: json(200, "{}"),
        };

        let fake_token = structurally_valid_group_send_token();

        Unauth(validator)
            .send_message(
                Aci::from(uuid::Uuid::try_parse(ACI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                vec![
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[0xff, 0xff]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[0xfe, 0xfe]),
                    },
                ],
                UserBasedSendAuthorization::User(UserBasedAuthorization::Group(fake_token)),
                true,
                false,
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test]
    fn test_individual_story_send() {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(const_str::concat!(
                    "/v1/messages/PNI:",
                    PNI_UUID,
                    "?story=true",
                )),
                headers: http::HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: Some(
                    compress_json!(
                        r#"{
                            "messages": [
                                {
                                    "type": 6,
                                    "destinationDeviceId": 2,
                                    "destinationRegistrationId": 22,
                                    "content": "//8="
                                },
                                {
                                    "type": 6,
                                    "destinationDeviceId": 3,
                                    "destinationRegistrationId": 33,
                                    "content": "/v4="
                                }
                            ],
                            "online": false,
                            "urgent": true,
                            "timestamp": 1700000000000
                        }"#
                    )
                    .into(),
                ),
            },
            response: json(200, "{}"),
        };

        Unauth(validator)
            .send_message(
                Pni::from(uuid::Uuid::try_parse(PNI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                vec![
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[0xff, 0xff]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[0xfe, 0xfe]),
                    },
                ],
                UserBasedSendAuthorization::Story,
                false,
                true,
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test_case(json(200, "{}") => matches Ok(MrResponse { unregistered_ids }) if unregistered_ids.is_empty())]
    #[test_case(json(200, r#"{"uuids404":[]}"#) => matches Ok(MrResponse { unregistered_ids }) if unregistered_ids.is_empty())]
    #[test_case(json(
        200, format!(r#"{{"uuids404":["{ACI_UUID}", "PNI:{PNI_UUID}"]}}"#)
    ) => matches Ok(MrResponse { unregistered_ids }) if unregistered_ids == [
        ServiceId::from(Aci::from(Uuid::try_parse(ACI_UUID).unwrap())),
        ServiceId::from(Pni::from(Uuid::try_parse(PNI_UUID).unwrap())),
    ])]
    #[test_case(json(200, r#"{"#) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(200, r#"{"uuids404":["garbage"]}"#) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(empty(401) => matches Err(RequestError::Other(MrFailure::Unauthorized)))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    #[test_case(empty(409) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        409, format!(r#"[
            {{"uuid":"{ACI_UUID}","devices":{{"missingDevices":[50,60]}}}},
            {{"uuid":"PNI:{PNI_UUID}","devices":{{"missingDevices":[],"extraDevices":[4,5]}}}}
        ]"#)
    ) => matches Err(RequestError::Other(MrFailure::MismatchedDevices(errors))) if errors == [
        MismatchedDeviceError {
            account: Aci::from(Uuid::try_parse(ACI_UUID).unwrap()).into(),
            missing_devices: vec![DeviceId::new(50).unwrap(), DeviceId::new(60).unwrap()],
            extra_devices: vec![],
            stale_devices: vec![],
        },
        MismatchedDeviceError {
            account: Pni::from(Uuid::try_parse(PNI_UUID).unwrap()).into(),
            missing_devices: vec![],
            extra_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
            stale_devices: vec![],
        },
    ])]
    #[test_case(json(
        410, format!(r#"[
            {{"uuid":"{ACI_UUID}","devices":{{"staleDevices":[4,5]}}}},
            {{"uuid":"PNI:{PNI_UUID}","devices":{{"staleDevices":[1]}}}}
        ]"#)
    ) => matches Err(RequestError::Other(MrFailure::MismatchedDevices(errors))) if errors == [
        MismatchedDeviceError {
            account: Aci::from(Uuid::try_parse(ACI_UUID).unwrap()).into(),
            missing_devices: vec![],
            extra_devices: vec![],
            stale_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
        },
        MismatchedDeviceError {
            account: Pni::from(Uuid::try_parse(PNI_UUID).unwrap()).into(),
            missing_devices: vec![],
            extra_devices: vec![],
            stale_devices: vec![DeviceId::new(1).unwrap()],
        },
    ])]
    #[test_case(json(
        410, r#"["#
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        410, format!(r#"{{"uuid":"{ACI_UUID}","devices":{{"staleDevices":[4,5]}}}}"#)
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        410, format!(r#"[{{"uuid":"{ACI_UUID}","devices":{{}}}}]"#)
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        410, r#"[{"uuid":"garbage","devices":{{"staleDevices":[4,5]}}}]"#
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        410, format!(r#"[{{"uuid":"{ACI_UUID}","devices":{{"staleDevices":[200]}}}}]"#)
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        410, format!(r#"[{{"uuid":"{ACI_UUID}","devices":{{"staleDevices":["4"]}}}}]"#)
    ) => matches Err(RequestError::Unexpected { .. }))]
    fn test_story(
        response: Response,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>> {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(
                    "/v1/messages/multi_recipient?ts=1700000000000&online=false&urgent=true&story=true",
                ),
                headers: http::HeaderMap::from_iter([(
                    http::header::CONTENT_TYPE,
                    MULTI_RECIPIENT_MESSAGE_CONTENT_TYPE,
                )]),
                body: Some(vec![1, 2, 3].into()),
            },
            response,
        };

        Unauth(validator)
            .send_multi_recipient_message(
                vec![1, 2, 3].into(),
                Timestamp::from_epoch_millis(1700000000000),
                MultiRecipientSendAuthorization::Story,
                false,
                true,
            )
            .now_or_never()
            .expect("sync")
    }

    #[test]
    fn test_group_send() {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(
                    "/v1/messages/multi_recipient?ts=1700000000000&online=true&urgent=false",
                ),
                headers: http::HeaderMap::from_iter([
                    (
                        http::header::CONTENT_TYPE,
                        MULTI_RECIPIENT_MESSAGE_CONTENT_TYPE,
                    ),
                    (
                        GROUP_SEND_TOKEN_HEADER,
                        http::HeaderValue::from_maybe_shared(
                            BASE64_STANDARD.encode(SERIALIZED_GROUP_SEND_TOKEN),
                        )
                        .expect("valid"),
                    ),
                ]),
                body: Some(vec![1, 2, 3].into()),
            },
            response: json(200, "{}"),
        };

        let fake_token = structurally_valid_group_send_token();
        let MultiRecipientMessageResponse { unregistered_ids } = Unauth(validator)
            .send_multi_recipient_message(
                vec![1, 2, 3].into(),
                Timestamp::from_epoch_millis(1700000000000),
                MultiRecipientSendAuthorization::Group(fake_token),
                true,
                false,
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
        assert_eq!(unregistered_ids, &[] as &[ServiceId]);
    }
}
