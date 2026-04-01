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
    CONTENT_TYPE_JSON, CustomError, GetUploadFormResponse, OverWs, TryIntoResponse, WsConnection,
    expect_empty_body, parse_json_from_body,
};
use crate::api::messages::{
    MismatchedDeviceError, MultiRecipientMessageResponse, MultiRecipientSendAuthorization,
    MultiRecipientSendFailure, SealedSendFailure, SingleOutboundSealedSenderMessage,
    SingleOutboundUnsealedMessage, UnauthenticatedChatApi, UnsealedSendFailure, UploadTooLarge,
    UserBasedSendAuthorization,
};
use crate::api::{Auth, RequestError, Unauth, UploadForm};
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

#[derive(Debug)]
struct MessageTypeCannotBeSentUnsealed;

impl TryFrom<libsignal_protocol::CiphertextMessageType> for EnvelopeType {
    type Error = MessageTypeCannotBeSentUnsealed;

    fn try_from(value: libsignal_protocol::CiphertextMessageType) -> Result<Self, Self::Error> {
        match value {
            libsignal_protocol::CiphertextMessageType::Whisper => Ok(Self::DoubleRatchet),
            libsignal_protocol::CiphertextMessageType::PreKey => Ok(Self::PreKey),
            libsignal_protocol::CiphertextMessageType::SenderKey => {
                Err(MessageTypeCannotBeSentUnsealed)
            }
            libsignal_protocol::CiphertextMessageType::Plaintext => Ok(Self::PlaintextContent),
        }
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

/// See [`SendMessageRequest`].
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
impl<T: WsConnection> UnauthenticatedChatApi<OverWs> for Unauth<T> {
    async fn send_message(
        &self,
        destination: ServiceId,
        timestamp: libsignal_protocol::Timestamp,
        contents: &[SingleOutboundSealedSenderMessage<'_>],
        auth: UserBasedSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<(), RequestError<SealedSendFailure>> {
        if let Some(grpc) = self.grpc_service_to_use_instead(
            services::MessagesAnonymous::SendSingleRecipientMessage.into(),
        ) {
            return Unauth(grpc)
                .send_message(destination, timestamp, contents, auth, online_only, urgent)
                .await;
        }

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

        assert!(!contents.is_empty(), "cannot send messages to 0 devices");

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
        if let Some(grpc) = self.grpc_service_to_use_instead(
            services::MessagesAnonymous::SendMultiRecipientMessage.into(),
        ) {
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

#[async_trait]
impl<T: WsConnection> crate::api::messages::AuthenticatedChatApi<OverWs> for Auth<T> {
    async fn send_message(
        &self,
        destination: ServiceId,
        timestamp: libsignal_protocol::Timestamp,
        contents: &[SingleOutboundUnsealedMessage<'_>],
        online_only: bool,
        urgent: bool,
    ) -> Result<(), RequestError<UnsealedSendFailure>> {
        if let Some(grpc) = self.grpc_service_to_use_instead(services::Messages::SendMessage.into())
        {
            return Auth(grpc)
                .send_message(destination, timestamp, contents, online_only, urgent)
                .await;
        }

        let path = format!("/v1/messages/{}", destination.service_id_string());
        let log_safe_path = format!(
            "/v1/messages/{} (ts: {})",
            Redact(destination),
            timestamp.epoch_millis()
        );

        SingleOutboundUnsealedMessage::assert_valid_unsealed_message_types(contents);

        let request = SendMessageRequest {
            messages: contents
                .iter()
                .map(|message| SingleOutboundMessageRepresentation {
                    message_type: message
                        .contents
                        .message_type()
                        .try_into()
                        .expect("checked above"),
                    destination_device_id: message.device_id.into(),
                    destination_registration_id: message.registration_id,
                    content: message.contents.serialize(),
                })
                .collect(),
            online: online_only,
            urgent,
            timestamp: timestamp.epoch_millis(),
        };

        let response = self
            .send(
                "auth",
                &log_safe_path,
                Request {
                    method: http::Method::PUT,
                    path: path.parse().expect("valid"),
                    headers: http::HeaderMap::from_iter([CONTENT_TYPE_JSON]),
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
                404 => {
                    expect_empty_body(response, "/v1/messages/*");
                    UnsealedSendFailure::ServiceIdNotFound.into()
                }
                409 | 410 => {
                    parse_single_recipient_mismatched_devices_response(destination, response)
                }
                _ => CustomError::NoCustomHandling,
            })
        })?;

        Ok(())
    }

    async fn send_sync_message(
        &self,
        timestamp: libsignal_protocol::Timestamp,
        contents: &[SingleOutboundUnsealedMessage<'_>],
        urgent: bool,
    ) -> Result<(), RequestError<MismatchedDeviceError>> {
        // Note that we check SendMessage here, not SendSyncMessage. We could change sync messages
        // to gRPC but leave unsealed non-sync messages as WS-based, but the other way around is not
        // supported (because of the way we've implemented this method to forward to send_message,
        // below). So to prevent any mistakes, we just use the same condition for both.
        if let Some(grpc) = self.grpc_service_to_use_instead(services::Messages::SendMessage.into())
        {
            return Auth(grpc)
                .send_sync_message(timestamp, contents, urgent)
                .await;
        }

        let self_aci = self
            .self_aci()
            .expect("cannot send sync message without getting self ACI from auth info");

        // The WS sync message API is "just" the regular send message API.
        self.send_message(self_aci.into(), timestamp, contents, false, urgent)
            .await
            .map_err(|e| {
                e.flat_map_other(|e| match e {
                    UnsealedSendFailure::ServiceIdNotFound => RequestError::Unexpected {
                        log_safe: "ServiceIdNotFound for sync message".to_string(),
                    },
                    UnsealedSendFailure::MismatchedDevices(mismatched_device_error) => {
                        RequestError::Other(mismatched_device_error)
                    }
                })
            })
    }

    async fn get_upload_form(
        &self,
        upload_length: u64,
    ) -> Result<UploadForm, RequestError<UploadTooLarge>> {
        if let Some(grpc) =
            self.grpc_service_to_use_instead(services::Attachments::GetUploadForm.into())
        {
            return Auth(grpc).get_upload_form(upload_length).await;
        }
        let path = format!("/v4/attachments/form/upload?uploadLength={upload_length}");
        let response = self
            .send(
                "auth",
                &path,
                Request {
                    method: http::Method::GET,
                    path: path.parse().expect("path should parse"),
                    headers: http::HeaderMap::default(),
                    body: None,
                },
            )
            .await?;

        let GetUploadFormResponse(upload_form) = response.try_into_response().map_err(|e| {
            e.into_request_error(Self::ALLOW_RATE_LIMIT_CHALLENGES, |response| {
                if response.status.as_u16() == 413 {
                    expect_empty_body(response, "/v4/attachments/form/upload");
                    CustomError::Err(UploadTooLarge)
                } else {
                    CustomError::NoCustomHandling
                }
            })
        })?;

        Ok(upload_form)
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

fn parse_single_recipient_mismatched_devices_response<E: From<MismatchedDeviceError>>(
    recipient: ServiceId,
    response: &Response,
) -> CustomError<E> {
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
        Ok(converted) => CustomError::Err(converted.into()),
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
    use libsignal_net::infra::errors::RetryLater;
    use libsignal_protocol::{CiphertextMessage, PlaintextContent, Timestamp};
    use serde_json::json;
    use test_case::test_case;
    use uuid::Uuid;

    use super::*;
    use crate::api::messages::AuthenticatedChatApi as _;
    use crate::api::testutil::{
        SERIALIZED_GROUP_SEND_TOKEN, TEST_SELF_ACI, structurally_valid_group_send_token,
    };
    use crate::api::{ChallengeOption, RateLimitChallenge, UserBasedAuthorization};
    use crate::ws::ACCESS_KEY_HEADER_NAME;
    use crate::ws::testutil::{JsonRequestValidator, RequestValidator, empty, json, with_headers};

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
        let validator = JsonRequestValidator {
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
                body: None,
            },
            body: json!({
                "messages": [
                    {
                        "type": 6,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "//8=",
                    },
                    {
                        "type": 6,
                        "destinationDeviceId": 3,
                        "destinationRegistrationId": 33,
                        "content": "/v4=",
                    }
                ],
                "online": false,
                "urgent": true,
                "timestamp": 1700000000000u64,
            }),
            response,
        };

        Unauth(validator)
            .send_message(
                Pni::from(uuid::Uuid::try_parse(PNI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
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
        let validator = JsonRequestValidator {
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
                body: None,
            },
            body: json!({
                "messages": [
                    {
                        "type": 6,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "//8=",
                    },
                    {
                        "type": 6,
                        "destinationDeviceId": 3,
                        "destinationRegistrationId": 33,
                        "content": "/v4=",
                    }
                ],
                "online": true,
                "urgent": false,
                "timestamp": 1700000000000u64,
            }),
            response: json(200, "{}"),
        };

        let fake_token = structurally_valid_group_send_token();

        Unauth(validator)
            .send_message(
                Aci::from(uuid::Uuid::try_parse(ACI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
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
    fn test_sealed_send_unrestricted_access() {
        let validator = JsonRequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(const_str::concat!(
                    "/v1/messages/",
                    ACI_UUID,
                )),
                headers: http::HeaderMap::from_iter([
                    CONTENT_TYPE_JSON,
                    (
                        ACCESS_KEY_HEADER_NAME,
                        http::HeaderValue::from_maybe_shared(BASE64_STANDARD.encode([0; 16]))
                            .expect("valid"),
                    ),
                ]),
                body: None,
            },
            body: json!({
                "messages": [
                    {
                        "type": 6,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "//8=",
                    },
                    {
                        "type": 6,
                        "destinationDeviceId": 3,
                        "destinationRegistrationId": 33,
                        "content": "/v4=",
                    }
                ],
                "online": true,
                "urgent": false,
                "timestamp": 1700000000000u64,
            }),
            response: json(200, "{}"),
        };

        Unauth(validator)
            .send_message(
                Aci::from(uuid::Uuid::try_parse(ACI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
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
                UserBasedAuthorization::UnrestrictedUnauthenticatedAccess.into(),
                true,
                false,
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test]
    fn test_individual_story_send() {
        let validator = JsonRequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(const_str::concat!(
                    "/v1/messages/PNI:",
                    PNI_UUID,
                    "?story=true",
                )),
                headers: http::HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: None,
            },
            body: json!({
                "messages": [
                    {
                        "type": 6,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "//8=",
                    },
                    {
                        "type": 6,
                        "destinationDeviceId": 3,
                        "destinationRegistrationId": 33,
                        "content": "/v4=",
                    }
                ],
                "online": false,
                "urgent": true,
                "timestamp": 1700000000000u64,
            }),
            response: json(200, "{}"),
        };

        Unauth(validator)
            .send_message(
                Pni::from(uuid::Uuid::try_parse(PNI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
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

    #[test_case(json(200, r#"{}"#) => matches Ok(()))]
    #[test_case(json(200, r#"{"needsSync":true}"#) => matches Ok(()))]
    #[test_case(empty(200) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(empty(404) => matches Err(RequestError::Other(UnsealedSendFailure::ServiceIdNotFound)))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    #[test_case(empty(409) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        409, r#"{"missingDevices":[50,60]}"#
    ) => matches Err(RequestError::Other(UnsealedSendFailure::MismatchedDevices(error))) if error ==
        MismatchedDeviceError {
            account: Pni::from(Uuid::try_parse(PNI_UUID).unwrap()).into(),
            missing_devices: vec![DeviceId::new(50).unwrap(), DeviceId::new(60).unwrap()],
            extra_devices: vec![],
            stale_devices: vec![],
        }
    )]
    #[test_case(json(
        409, r#"{"missingDevices":[],"extraDevices":[4,5]}"#
    ) => matches Err(RequestError::Other(UnsealedSendFailure::MismatchedDevices(error))) if error ==
        MismatchedDeviceError {
            account: Pni::from(Uuid::try_parse(PNI_UUID).unwrap()).into(),
            missing_devices: vec![],
            extra_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
            stale_devices: vec![],
        }
    )]
    #[test_case(json(
        410, r#"{"staleDevices":[4,5]}"#
    ) => matches Err(RequestError::Other(UnsealedSendFailure::MismatchedDevices(error))) if error ==
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
    #[test_case(empty(428) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("428"))]
    #[test_case(json(428, "{}") => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("428"))]
    #[test_case(json(
        428, r#"{"token": "zzz", "options": ["captcha"]}"#
    ) => matches Err(RequestError::Challenge(RateLimitChallenge { token, options, retry_later: None })) if token == "zzz" && options == vec![ChallengeOption::Captcha])]
    #[test_case(with_headers(&[(http::header::RETRY_AFTER, "42")], json(
        428, r#"{"token": "zzz", "options": ["captcha"]}"#
    )) => matches Err(RequestError::Challenge(RateLimitChallenge { token, options, retry_later: Some(
        RetryLater { retry_after_seconds: 42 }
    ) })) if token == "zzz" && options == vec![ChallengeOption::Captcha])]
    fn test_unsealed_send(response: Response) -> Result<(), RequestError<UnsealedSendFailure>> {
        let validator = JsonRequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::from_static(const_str::concat!(
                    "/v1/messages/PNI:",
                    PNI_UUID
                )),
                headers: http::HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: None,
            },
            body: json!({
                "messages": [
                    {
                        "type": 8,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "wAECA4A="
                    },
                    {
                        "type": 8,
                        "destinationDeviceId": 3,
                        "destinationRegistrationId": 33,
                        "content": "wAQFBoA="
                    }
                ],
                "online": false,
                "urgent": true,
                "timestamp": 1700000000000u64
            }),
            response,
        };

        Auth(validator)
            .send_message(
                Pni::from(uuid::Uuid::try_parse(PNI_UUID).expect("valid")).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
                    SingleOutboundUnsealedMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Owned(CiphertextMessage::PlaintextContent(
                            PlaintextContent::try_from(
                                // A structurally valid PlaintextContent message starts with C0 and has
                                // no other constraints; a realistic one will additionally end with
                                // "padding" of 80 followed by any number of 00 bytes.
                                &[0xC0, 1, 2, 3, 0x80][..],
                            )
                            .expect("valid"),
                        )),
                    },
                    SingleOutboundUnsealedMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Owned(CiphertextMessage::PlaintextContent(
                            PlaintextContent::try_from(&[0xC0, 4, 5, 6, 0x80][..]).expect("valid"),
                        )),
                    },
                ],
                false,
                true,
            )
            .now_or_never()
            .expect("sync")
    }

    #[test_case(json(200, r#"{}"#) => matches Ok(()))]
    #[test_case(json(200, r#"{"needsSync":true}"#) => matches Ok(()))]
    #[test_case(empty(200) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(empty(404) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    #[test_case(empty(409) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(json(
        409, r#"{"missingDevices":[50,60]}"#
    ) => matches Err(RequestError::Other(error)) if error ==
        MismatchedDeviceError {
            account: TEST_SELF_ACI.into(),
            missing_devices: vec![DeviceId::new(50).unwrap(), DeviceId::new(60).unwrap()],
            extra_devices: vec![],
            stale_devices: vec![],
        }
    )]
    #[test_case(json(
        410, r#"{"staleDevices":[4,5]}"#
    ) => matches Err(RequestError::Other(error)) if error ==
        MismatchedDeviceError {
            account: TEST_SELF_ACI.into(),
            missing_devices: vec![],
            extra_devices: vec![],
            stale_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
        }
    )]
    #[test_case(json(
        428, r#"{"token": "zzz", "options": ["captcha"]}"#
    ) => matches Err(RequestError::Challenge(RateLimitChallenge { token, options, retry_later: None })) if token == "zzz" && options == vec![ChallengeOption::Captcha])]
    fn test_sync_send(response: Response) -> Result<(), RequestError<MismatchedDeviceError>> {
        let validator = JsonRequestValidator {
            expected: Request {
                method: http::Method::PUT,
                path: http::uri::PathAndQuery::try_from(format!(
                    "/v1/messages/{}",
                    TEST_SELF_ACI.service_id_string()
                ))
                .expect("valid"),
                headers: http::HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: None,
            },
            body: json!({
                "messages": [
                    {
                        "type": 8,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "wAECA4A="
                    },
                    {
                        "type": 8,
                        "destinationDeviceId": 3,
                        "destinationRegistrationId": 33,
                        "content": "wAQFBoA="
                    }
                ],
                "online": false,
                "urgent": true,
                "timestamp": 1700000000000u64
            }),
            response,
        };

        Auth(validator)
            .send_sync_message(
                Timestamp::from_epoch_millis(1700000000000),
                &[
                    SingleOutboundUnsealedMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Owned(CiphertextMessage::PlaintextContent(
                            PlaintextContent::try_from(
                                // A structurally valid PlaintextContent message starts with C0 and has
                                // no other constraints; a realistic one will additionally end with
                                // "padding" of 80 followed by any number of 00 bytes.
                                &[0xC0, 1, 2, 3, 0x80][..],
                            )
                            .expect("valid"),
                        )),
                    },
                    SingleOutboundUnsealedMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Owned(CiphertextMessage::PlaintextContent(
                            PlaintextContent::try_from(&[0xC0, 4, 5, 6, 0x80][..]).expect("valid"),
                        )),
                    },
                ],
                true,
            )
            .now_or_never()
            .expect("sync")
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

    #[test_case(json(200, r#"{
        "cdn":123,
        "key":"abcde",
        "headers":{"one":"val1","two":"val2"},
        "signedUploadLocation":"http://example.org/upload"
    }"#) => matches Ok(form) if form == UploadForm {
        cdn: 123,
        key: "abcde".into(),
        headers: vec![("one".into(), "val1".into()), ("two".into(), "val2".into())],
        signed_upload_url: "http://example.org/upload".into(),
    })]
    #[test_case(empty(413) => matches Err(RequestError::Other(UploadTooLarge)))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    fn test_get_upload_form(
        response: Response,
    ) -> Result<UploadForm, RequestError<UploadTooLarge>> {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static(
                    "/v4/attachments/form/upload?uploadLength=12345",
                ),
                headers: http::HeaderMap::default(),
                body: None,
            },
            response,
        };

        Auth(validator)
            .get_upload_form(12345)
            .now_or_never()
            .expect("sync")
    }
}
