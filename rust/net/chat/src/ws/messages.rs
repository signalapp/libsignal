//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use assert_matches::debug_assert_matches;
use async_trait::async_trait;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use itertools::Itertools as _;
use libsignal_core::{DeviceId, ServiceId};
use libsignal_net::chat::{Request, Response};

use super::{CustomError, TryIntoResponse, WsConnection, parse_json_from_body};
use crate::api::messages::{
    MismatchedDeviceError, MultiRecipientMessageResponse, MultiRecipientSendAuthorization,
    MultiRecipientSendFailure,
};
use crate::api::{RequestError, Unauth};

const GROUP_SEND_TOKEN_HEADER: http::HeaderName = http::HeaderName::from_static("group-send-token");
const MULTI_RECIPIENT_MESSAGE_CONTENT_TYPE: http::HeaderValue =
    http::HeaderValue::from_static("application/vnd.signal-messenger.mrm");

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

#[async_trait]
impl<T: WsConnection> crate::api::messages::UnauthenticatedChatApi for Unauth<T> {
    async fn send_multi_recipient_message(
        &self,
        payload: bytes::Bytes,
        timestamp: libsignal_protocol::Timestamp,
        auth: MultiRecipientSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>> {
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
                e.into_request_error(|response| match response.status.as_u16() {
                    401 => {
                        if !response.body.as_deref().unwrap_or_default().is_empty() {
                            log::warn!(
                                "ignoring body for 401 result from send_multi_recipient_message"
                            );
                        }
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

    // Note: this can be shared with the 1:1 mismatched devices response.
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

    fn validate_device_id(
        input: u8,
        label: &'static str,
    ) -> Result<DeviceId, CustomError<MultiRecipientSendFailure>> {
        DeviceId::new(input).map_err(|_| CustomError::Unexpected {
            log_safe: format!("invalid device ID {input} in {label} array"),
        })
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
            if devices == Default::default() {
                return Err(CustomError::Unexpected {
                    log_safe: "no devices listed in mismatched device response".to_owned(),
                });
            }
            let ParsedMismatchedDevices {
                missing_devices,
                extra_devices,
                stale_devices,
            } = devices;

            Ok(MismatchedDeviceError {
                account: ServiceId::parse_from_service_id_string(&service_id).ok_or_else(|| {
                    CustomError::Unexpected {
                        log_safe: "could not parse ServiceId in mismatched device response"
                            .to_owned(),
                    }
                })?,
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
        })
        .try_collect();
    match per_recipient_errors {
        Ok(errors) => MultiRecipientSendFailure::MismatchedDevices(errors).into(),
        Err(e) => e,
    }
}

#[cfg(test)]
mod test {
    use const_str::concat_bytes;
    use futures_util::FutureExt;
    use libsignal_core::{Aci, Pni};
    use libsignal_protocol::Timestamp;
    use test_case::test_case;
    use uuid::Uuid;

    use super::*;
    use crate::api::messages::UnauthenticatedChatApi;
    use crate::ws::testutil::{RequestValidator, empty, json};

    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const PNI_UUID: &str = "796abedb-ca4e-4f18-8803-1fde5b921f9f";

    type MrResponse = MultiRecipientMessageResponse;
    type MrFailure = MultiRecipientSendFailure;

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
                        http::HeaderValue::from_static(
                            "ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo5c+LAQAA",
                        ),
                    ),
                ]),
                body: Some(vec![1, 2, 3].into()),
            },
            response: json(200, "{}"),
        };

        // A full token is a version byte, a length-prefixed truncated hash, and a 64-bit
        // day-aligned expiration timestamp in seconds.
        let fake_token = zkgroup::deserialize(concat_bytes!(
            0,
            16u64.to_le_bytes(),
            [0; 16],
            1700000000000u64.to_le_bytes()
        ))
        .expect("valid (enough)");

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
