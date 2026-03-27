//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::fmt::Formatter;

use async_trait::async_trait;
use itertools::Itertools as _;
use libsignal_core::{DeviceId, ServiceId};
use libsignal_net_grpc::proto::chat::attachments::attachments_client::AttachmentsClient;
use libsignal_net_grpc::proto::chat::common::ServiceIdentifier;
use libsignal_net_grpc::proto::chat::messages::messages_anonymous_client::MessagesAnonymousClient;
use libsignal_net_grpc::proto::chat::messages::{
    MismatchedDevices, MultiRecipientMessage, MultiRecipientMismatchedDevices,
    MultiRecipientSuccess, SendMultiRecipientMessageRequest, SendMultiRecipientMessageResponse,
    SendMultiRecipientStoryRequest, send_multi_recipient_message_response,
};
use libsignal_net_grpc::proto::chat::{attachments, common, errors};
use libsignal_protocol::Timestamp;

use super::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::api::messages::{
    MismatchedDeviceError, MultiRecipientMessageResponse, MultiRecipientSendAuthorization,
    MultiRecipientSendFailure, SealedSendFailure, SingleOutboundSealedSenderMessage,
    SingleOutboundUnsealedMessage, UnsealedSendFailure, UserBasedSendAuthorization,
};
use crate::api::{Auth, RequestError, Unauth, UploadForm};
use crate::logging::Redact;

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::messages::UnauthenticatedChatApi<OverGrpc> for Unauth<T> {
    async fn send_message(
        &self,
        _destination: ServiceId,
        _timestamp: libsignal_protocol::Timestamp,
        _contents: &[SingleOutboundSealedSenderMessage<'_>],
        _auth: UserBasedSendAuthorization,
        _online_only: bool,
        _urgent: bool,
    ) -> Result<(), RequestError<SealedSendFailure>> {
        unimplemented!()
    }

    async fn send_multi_recipient_message(
        &self,
        payload: bytes::Bytes,
        timestamp: libsignal_protocol::Timestamp,
        auth: MultiRecipientSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>> {
        let mut service = MessagesAnonymousClient::new(self.0.service());

        let message = Some(MultiRecipientMessage {
            timestamp: timestamp.epoch_millis(),
            payload: payload.into(),
        });

        let SendMultiRecipientMessageResponse { response } = match auth {
            MultiRecipientSendAuthorization::Story => {
                assert!(!online_only, "stories should never be sent online-only");
                let request = SendMultiRecipientStoryRequest { urgent, message };
                let log_safe_description = Redact(&request).to_string();
                log_and_send("unauth", &log_safe_description, || {
                    service.send_multi_recipient_story(request)
                })
                .await?
                .into_inner()
            }

            MultiRecipientSendAuthorization::Group(group_send_full_token) => {
                let request = SendMultiRecipientMessageRequest {
                    ephemeral: online_only,
                    urgent,
                    message,
                    group_send_token: zkgroup::serialize(&group_send_full_token),
                };
                let log_safe_description = Redact(&request).to_string();

                log_and_send("unauth", &log_safe_description, || {
                    service.send_multi_recipient_message(request)
                })
                .await?
                .into_inner()
            }
        };

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        match response {
            send_multi_recipient_message_response::Response::Success(MultiRecipientSuccess {
                unresolved_recipients,
            }) => Ok(MultiRecipientMessageResponse {
                unregistered_ids: unresolved_recipients
                    .into_iter()
                    .map(|id| {
                        id.try_as_service_id()
                            .ok_or_else(|| RequestError::Unexpected {
                                log_safe: "unable to parse ServiceId in unresolved_recipients"
                                    .to_owned(),
                            })
                    })
                    .try_collect()?,
            }),
            send_multi_recipient_message_response::Response::FailedUnidentifiedAuthorization(
                errors::FailedUnidentifiedAuthorization { description },
            ) => {
                log::warn!("failed auth: {description}");
                Err(RequestError::Other(MultiRecipientSendFailure::Unauthorized))
            }
            send_multi_recipient_message_response::Response::MismatchedDevices(
                MultiRecipientMismatchedDevices { mismatched_devices },
            ) => {
                if mismatched_devices.is_empty() {
                    return Err(RequestError::Unexpected {
                        log_safe: "no devices listed in mismatched device response".to_owned(),
                    });
                }

                fn validate_device_id(
                    input: u32,
                    label: &'static str,
                ) -> Result<DeviceId, RequestError<MultiRecipientSendFailure>> {
                    input
                        .try_into()
                        .ok()
                        .and_then(|input| DeviceId::new(input).ok())
                        .ok_or_else(|| RequestError::Unexpected {
                            log_safe: format!("invalid device ID {input} in {label} array"),
                        })
                }

                Err(RequestError::Other(
                    MultiRecipientSendFailure::MismatchedDevices(
                        mismatched_devices
                            .into_iter()
                            .map(|next| -> Result<_, RequestError<_>> {
                                let MismatchedDevices {
                                    service_identifier,
                                    missing_devices,
                                    extra_devices,
                                    stale_devices,
                                } = next;

                                if missing_devices.is_empty()
                                    && extra_devices.is_empty()
                                    && stale_devices.is_empty()
                                {
                                    return Err(RequestError::Unexpected {
                                        log_safe: "no devices listed for account in mismatched device response"
                                            .to_owned(),
                                    });
                                }

                                Ok(MismatchedDeviceError {
                                    account: service_identifier
                                        .as_ref()
                                        .and_then(ServiceIdentifier::try_as_service_id)
                                        .ok_or_else(|| RequestError::Unexpected {
                                            log_safe:
                                                "unable to parse ServiceId in mismatched_devices"
                                                    .to_owned(),
                                        })?,
                                    missing_devices: missing_devices
                                        .into_iter()
                                        .map(|id| validate_device_id(id, "missing_devices"))
                                        .try_collect()?,
                                    extra_devices: extra_devices
                                        .into_iter()
                                        .map(|id| validate_device_id(id, "extra_devices"))
                                        .try_collect()?,
                                    stale_devices: stale_devices
                                        .into_iter()
                                        .map(|id| validate_device_id(id, "stale_devices"))
                                        .try_collect()?,
                                })
                            })
                            .try_collect()?,
                    ),
                ))
            }
        }
    }
}

impl std::fmt::Display for Redact<SendMultiRecipientStoryRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SendMultiRecipientStoryRequest { urgent, message }) = self;
        f.debug_struct("SendMultiRecipientStoryRequest")
            .field("timestamp", &message.as_ref().map_or(0, |m| m.timestamp))
            .field("urgent", urgent)
            .finish()
    }
}

impl std::fmt::Display for Redact<SendMultiRecipientMessageRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SendMultiRecipientMessageRequest {
            ephemeral,
            urgent,
            message,
            group_send_token: _,
        }) = self;
        f.debug_struct("SendMultiRecipientMessageRequest")
            .field("timestamp", &message.as_ref().map_or(0, |m| m.timestamp))
            .field("ephemeral", ephemeral)
            .field("urgent", urgent)
            .finish()
    }
}

impl std::fmt::Display for Redact<attachments::GetUploadFormRequest> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let Self(attachments::GetUploadFormRequest {}) = self;
        f.debug_struct("attachments::GetUploadFormRequest").finish()
    }
}

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::messages::AuthenticatedChatApi<OverGrpc> for Auth<T> {
    async fn send_message(
        &self,
        _destination: ServiceId,
        _timestamp: Timestamp,
        _contents: &[SingleOutboundUnsealedMessage<'_>],
        _online_only: bool,
        _urgent: bool,
    ) -> Result<(), RequestError<UnsealedSendFailure>> {
        unimplemented!()
    }

    async fn send_sync_message(
        &self,
        _timestamp: Timestamp,
        _contents: &[SingleOutboundUnsealedMessage<'_>],
        _urgent: bool,
    ) -> Result<(), RequestError<MismatchedDeviceError>> {
        unimplemented!()
    }

    async fn get_upload_form(&self) -> Result<UploadForm, RequestError<Infallible>> {
        let mut attachments_service = AttachmentsClient::new(self.0.service());
        let request = attachments::GetUploadFormRequest {};
        let log_safe_description = Redact(&request).to_string();
        let attachments::GetUploadFormResponse { upload_form } =
            log_and_send("auth", &log_safe_description, || {
                attachments_service.get_upload_form(request)
            })
            .await?
            .into_inner();
        let common::UploadForm {
            cdn,
            key,
            headers,
            signed_upload_location,
        } = upload_form.ok_or_else(|| RequestError::Unexpected {
            log_safe: "GetUploadFormResponse missing upload form".to_string(),
        })?;
        Ok(UploadForm {
            cdn,
            key,
            headers: headers.into_iter().collect(),
            signed_upload_url: signed_upload_location,
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use futures_util::FutureExt as _;
    use libsignal_core::{Aci, Pni, ServiceId};
    use libsignal_net_grpc::proto::chat::services;
    use libsignal_protocol::Timestamp;
    use test_case::test_case;
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::api::messages::{AuthenticatedChatApi, UnauthenticatedChatApi as _};
    use crate::api::testutil::{SERIALIZED_GROUP_SEND_TOKEN, structurally_valid_group_send_token};
    use crate::grpc::testutil::{GrpcOverrideRequestValidator, RequestValidator, err, ok, req};

    const ACI_UUID: Uuid = uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
    const PNI_UUID: Uuid = uuid!("796abedb-ca4e-4f18-8803-1fde5b921f9f");

    type MrResponse = MultiRecipientMessageResponse;
    type MrFailure = MultiRecipientSendFailure;

    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::Success(MultiRecipientSuccess {
            unresolved_recipients: vec![]
        })),
    }) => matches Ok(MrResponse { unregistered_ids }) if unregistered_ids.is_empty())]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::Success(MultiRecipientSuccess {
            unresolved_recipients: vec![
                ServiceIdentifier::from(Aci::from(ACI_UUID)),
                ServiceIdentifier::from(Pni::from(PNI_UUID)),
            ],
        })),
    }) => matches Ok(MrResponse { unregistered_ids }) if unregistered_ids == [
        ServiceId::from(Aci::from(ACI_UUID)),
        ServiceId::from(Pni::from(PNI_UUID)),
    ])]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::Success(MultiRecipientSuccess {
            unresolved_recipients: vec![
                ServiceIdentifier::default(),
            ],
        })),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::FailedUnidentifiedAuthorization(
            errors::FailedUnidentifiedAuthorization {
                description: "too bad".to_owned(),
            },
        )),
    }) => matches Err(RequestError::Other(MrFailure::Unauthorized)))]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::MismatchedDevices(
            MultiRecipientMismatchedDevices {
                mismatched_devices: vec![],
            },
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::MismatchedDevices(
            MultiRecipientMismatchedDevices {
                mismatched_devices: vec![
                    MismatchedDevices {
                        service_identifier: Some(Aci::from(ACI_UUID).into()),
                        missing_devices: vec![50, 60],
                        extra_devices: vec![],
                        stale_devices: vec![70, 80],
                    },
                    MismatchedDevices {
                        service_identifier: Some(Pni::from(PNI_UUID).into()),
                        missing_devices: vec![],
                        extra_devices: vec![4, 5],
                        stale_devices: vec![],
                    },
                ],
            },
        )),
    }) => matches Err(RequestError::Other(MrFailure::MismatchedDevices(errors))) if errors == [
        MismatchedDeviceError {
            account: Aci::from(ACI_UUID).into(),
            missing_devices: vec![DeviceId::new(50).unwrap(), DeviceId::new(60).unwrap()],
            extra_devices: vec![],
            stale_devices: vec![DeviceId::new(70).unwrap(), DeviceId::new(80).unwrap()],
        },
        MismatchedDeviceError {
            account: Pni::from(PNI_UUID).into(),
            missing_devices: vec![],
            extra_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
            stale_devices: vec![],
        },
    ])]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::MismatchedDevices(
            MultiRecipientMismatchedDevices {
                mismatched_devices: vec![
                    MismatchedDevices {
                        service_identifier: Some(Aci::from(ACI_UUID).into()),
                        missing_devices: vec![50, 60],
                        extra_devices: vec![],
                        stale_devices: vec![70, 80],
                    },
                    MismatchedDevices {
                        service_identifier: Some(Pni::from(PNI_UUID).into()),
                        missing_devices: vec![],
                        extra_devices: vec![],
                        stale_devices: vec![],
                    },
                ],
            },
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::MismatchedDevices(
            MultiRecipientMismatchedDevices {
                mismatched_devices: vec![
                    MismatchedDevices {
                        service_identifier: Some(Aci::from(ACI_UUID).into()),
                        missing_devices: vec![50, 60],
                        extra_devices: vec![],
                        stale_devices: vec![70, 80],
                    },
                    MismatchedDevices {
                        service_identifier: None,
                        missing_devices: vec![],
                        extra_devices: vec![4, 5],
                        stale_devices: vec![],
                    },
                ],
            },
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMultiRecipientMessageResponse {
        response: Some(send_multi_recipient_message_response::Response::MismatchedDevices(
            MultiRecipientMismatchedDevices {
                mismatched_devices: vec![
                    MismatchedDevices {
                        service_identifier: Some(Aci::from(ACI_UUID).into()),
                        missing_devices: vec![50, 60],
                        extra_devices: vec![],
                        stale_devices: vec![70, 80],
                    },
                    MismatchedDevices {
                        service_identifier: Some(Pni::from(PNI_UUID).into()),
                        missing_devices: vec![],
                        extra_devices: vec![5000],
                        stale_devices: vec![],
                    },
                ],
            },
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(err(tonic::Code::Internal) => matches Err(RequestError::Unexpected { .. }))]
    fn test_story(
        response: http::Response<Vec<u8>>,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>> {
        let validator = GrpcOverrideRequestValidator {
            message: services::MessagesAnonymous::SendMultiRecipientMessage.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.messages.MessagesAnonymous/SendMultiRecipientStory",
                    SendMultiRecipientStoryRequest {
                        urgent: true,
                        message: Some(MultiRecipientMessage {
                            timestamp: 1700000000000,
                            payload: vec![1, 2, 3],
                        }),
                    },
                ),
                response,
            },
        };

        Unauth(&validator)
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
    #[should_panic(expected = "online-only")]
    fn ephemeral_story_is_not_allowed() {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.messages.MessagesAnonymous/SendMultiRecipientStory",
                SendMultiRecipientStoryRequest::default(),
            ),
            response: err(tonic::Code::FailedPrecondition),
        };

        _ = Unauth(&validator)
            .send_multi_recipient_message(
                vec![1, 2, 3].into(),
                Timestamp::from_epoch_millis(1700000000000),
                MultiRecipientSendAuthorization::Story,
                true,
                true,
            )
            .now_or_never()
            .expect("sync");
    }

    #[test]
    fn test_group_send() {
        let validator = GrpcOverrideRequestValidator {
            message: services::MessagesAnonymous::SendMultiRecipientMessage.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.messages.MessagesAnonymous/SendMultiRecipientMessage",
                    SendMultiRecipientMessageRequest {
                        ephemeral: true,
                        urgent: false,
                        message: Some(MultiRecipientMessage {
                            timestamp: 1700000000000,
                            payload: vec![1, 2, 3],
                        }),
                        group_send_token: SERIALIZED_GROUP_SEND_TOKEN.to_vec(),
                    },
                ),
                response: ok(SendMultiRecipientMessageResponse {
                    response: Some(send_multi_recipient_message_response::Response::Success(
                        Default::default(),
                    )),
                }),
            },
        };

        let fake_token = structurally_valid_group_send_token();

        let MultiRecipientMessageResponse { unregistered_ids } = Unauth(&validator)
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

    #[test]
    fn test_attachment_get_upload_form() {
        let validator = GrpcOverrideRequestValidator {
            message: services::Attachments::GetUploadForm.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.attachments.Attachments/GetUploadForm",
                    attachments::GetUploadFormRequest {},
                ),
                response: ok(attachments::GetUploadFormResponse {
                    upload_form: Some(common::UploadForm {
                        cdn: 2,
                        key: "my key".to_string(),
                        headers: HashMap::from_iter([
                            ("one".to_string(), "val1".to_string()),
                            ("two".to_string(), "val2".to_string()),
                        ]),
                        signed_upload_location: "location".to_string(),
                    }),
                }),
            },
        };
        let mut upload_form = Auth(&validator)
            .get_upload_form()
            .now_or_never()
            .expect("sync")
            .expect("success");
        upload_form.headers.sort(); // HashMap is non-deterministic
        assert_eq!(
            upload_form,
            UploadForm {
                cdn: 2,
                key: "my key".to_string(),
                headers: vec![
                    ("one".to_string(), "val1".to_string()),
                    ("two".to_string(), "val2".to_string()),
                ],
                signed_upload_url: "location".to_string(),
            }
        );
    }
}
