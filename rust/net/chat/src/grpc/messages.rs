//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Formatter;

use async_trait::async_trait;
use itertools::Itertools as _;
use libsignal_core::{DeviceId, ServiceId};
use libsignal_net_grpc::proto::chat::attachments::attachments_client::AttachmentsClient;
use libsignal_net_grpc::proto::chat::attachments::get_upload_form_response::Outcome;
use libsignal_net_grpc::proto::chat::common::ServiceIdentifier;
use libsignal_net_grpc::proto::chat::messages::messages_anonymous_client::MessagesAnonymousClient;
use libsignal_net_grpc::proto::chat::messages::messages_client::MessagesClient;
use libsignal_net_grpc::proto::chat::messages::{
    IndividualRecipientMessageBundle, MismatchedDevices, MultiRecipientMessage,
    MultiRecipientMismatchedDevices, MultiRecipientSuccess, SendAuthenticatedSenderMessageRequest,
    SendMessageAuthenticatedSenderResponse, SendMessageResponse, SendMessageType,
    SendMultiRecipientMessageRequest, SendMultiRecipientMessageResponse,
    SendMultiRecipientStoryRequest, SendSealedSenderMessageRequest, SendStoryMessageRequest,
    SendSyncMessageRequest, individual_recipient_message_bundle,
    send_message_authenticated_sender_response, send_message_response,
    send_multi_recipient_message_response, send_sealed_sender_message_request,
};
use libsignal_net_grpc::proto::chat::{attachments, common, errors};
use libsignal_protocol::Timestamp;

use super::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::api::messages::{
    MismatchedDeviceError, MultiRecipientMessageResponse, MultiRecipientSendAuthorization,
    MultiRecipientSendFailure, SealedSendFailure, SingleOutboundSealedSenderMessage,
    SingleOutboundUnsealedMessage, UnsealedSendFailure, UploadTooLarge, UserBasedSendAuthorization,
};
use crate::api::{Auth, RequestError, Unauth, UploadForm, UserBasedAuthorization};
use crate::logging::Redact;

impl From<UserBasedAuthorization> for send_sealed_sender_message_request::Authorization {
    fn from(value: UserBasedAuthorization) -> Self {
        match value {
            UserBasedAuthorization::AccessKey(uak) => Self::UnidentifiedAccessKey(uak.to_vec()),
            UserBasedAuthorization::Group(token) => {
                Self::GroupSendToken(zkgroup::serialize(&token))
            }
            UserBasedAuthorization::UnrestrictedUnauthenticatedAccess => {
                Self::UnrestrictedAccess(())
            }
        }
    }
}

#[derive(Debug)]
struct MessageTypeCannotBeSentUnsealed;

impl SingleOutboundUnsealedMessage<'_> {
    fn grpc_unsealed_message_type(
        &self,
    ) -> Result<SendMessageType, MessageTypeCannotBeSentUnsealed> {
        match self.contents.message_type() {
            libsignal_protocol::CiphertextMessageType::Whisper => {
                Ok(SendMessageType::DoubleRatchet)
            }
            libsignal_protocol::CiphertextMessageType::PreKey => Ok(SendMessageType::PrekeyMessage),
            libsignal_protocol::CiphertextMessageType::SenderKey => {
                Err(MessageTypeCannotBeSentUnsealed)
            }
            libsignal_protocol::CiphertextMessageType::Plaintext => {
                Ok(SendMessageType::PlaintextContent)
            }
        }
    }
}

impl TryFrom<MismatchedDevices> for MismatchedDeviceError {
    type Error = RequestError<std::convert::Infallible>;

    fn try_from(value: MismatchedDevices) -> Result<Self, Self::Error> {
        fn validate_device_id(
            input: u32,
            label: &'static str,
        ) -> Result<DeviceId, RequestError<std::convert::Infallible>> {
            input
                .try_into()
                .ok()
                .and_then(|input| DeviceId::new(input).ok())
                .ok_or_else(|| RequestError::Unexpected {
                    log_safe: format!("invalid device ID {input} in {label} array"),
                })
        }

        let MismatchedDevices {
            service_identifier,
            missing_devices,
            extra_devices,
            stale_devices,
        } = value;

        if missing_devices.is_empty() && extra_devices.is_empty() && stale_devices.is_empty() {
            return Err(RequestError::Unexpected {
                log_safe: "no devices listed for account in mismatched device response".to_owned(),
            });
        }

        Ok(MismatchedDeviceError {
            account: service_identifier
                .as_ref()
                .and_then(ServiceIdentifier::try_as_service_id)
                .ok_or_else(|| RequestError::Unexpected {
                    log_safe: "unable to parse ServiceId in mismatched_devices".to_owned(),
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
    }
}

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::messages::UnauthenticatedChatApi<OverGrpc> for Unauth<T> {
    async fn send_message(
        &self,
        destination: ServiceId,
        timestamp: Timestamp,
        contents: &[SingleOutboundSealedSenderMessage<'_>],
        auth: UserBasedSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<(), RequestError<SealedSendFailure>> {
        let mut service = MessagesAnonymousClient::new(self.0.service());

        assert!(!contents.is_empty(), "cannot send messages to 0 devices");

        let messages = Some(IndividualRecipientMessageBundle {
            timestamp: timestamp.epoch_millis(),
            messages: contents
                .iter()
                .map(|message| {
                    (
                        message.device_id.into(),
                        individual_recipient_message_bundle::Message {
                            registration_id: message.registration_id,
                            payload: message.contents.to_vec(),
                            r#type: SendMessageType::UnidentifiedSender.into(),
                        },
                    )
                })
                .collect(),
        });

        let SendMessageResponse { response } = match auth {
            UserBasedSendAuthorization::Story => {
                assert!(!online_only, "stories should never be sent online-only");
                let request = SendStoryMessageRequest {
                    destination: Some(destination.into()),
                    urgent,
                    messages,
                };

                let log_safe_description = Redact(&request).to_string();
                log_and_send("auth", &log_safe_description, || {
                    service.send_story(request)
                })
                .await?
                .into_inner()
            }
            UserBasedSendAuthorization::User(auth) => {
                let request = SendSealedSenderMessageRequest {
                    destination: Some(destination.into()),
                    ephemeral: online_only,
                    urgent,
                    messages,
                    authorization: Some(auth.into()),
                };
                let log_safe_description = Redact(&request).to_string();
                log_and_send("auth", &log_safe_description, || {
                    service.send_single_recipient_message(request)
                })
                .await?
                .into_inner()
            }
        };

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        match response {
            send_message_response::Response::Success(()) => Ok(()),
            send_message_response::Response::FailedUnidentifiedAuthorization(
                errors::FailedUnidentifiedAuthorization { description },
            ) => {
                log::warn!("failed auth: {description}");
                Err(RequestError::Other(SealedSendFailure::Unauthorized))
            }
            send_message_response::Response::MismatchedDevices(mismatched_devices) => {
                Err(RequestError::Other(
                    MismatchedDeviceError::try_from(mismatched_devices)
                        .map_err(RequestError::with_other)?
                        .into(),
                ))
            }
            send_message_response::Response::DestinationNotFound(errors::NotFound {}) => {
                Err(RequestError::Other(SealedSendFailure::ServiceIdNotFound))
            }
        }
    }

    async fn send_multi_recipient_message(
        &self,
        payload: bytes::Bytes,
        timestamp: Timestamp,
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

                Err(RequestError::Other(
                    MultiRecipientSendFailure::MismatchedDevices(
                        mismatched_devices
                            .into_iter()
                            .map(|next| next.try_into())
                            .try_collect()
                            .map_err(|e: RequestError<_>| e.with_other())?,
                    ),
                ))
            }
        }
    }
}

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::messages::AuthenticatedChatApi<OverGrpc> for Auth<T> {
    async fn send_message(
        &self,
        destination: ServiceId,
        timestamp: Timestamp,
        contents: &[SingleOutboundUnsealedMessage<'_>],
        online_only: bool,
        urgent: bool,
    ) -> Result<(), RequestError<UnsealedSendFailure>> {
        SingleOutboundUnsealedMessage::assert_valid_unsealed_message_types(contents);

        let mut service = MessagesClient::new(self.0.service());
        let request = SendAuthenticatedSenderMessageRequest {
            destination: Some(destination.into()),
            ephemeral: online_only,
            urgent,
            messages: Some(IndividualRecipientMessageBundle {
                timestamp: timestamp.epoch_millis(),
                messages: contents
                    .iter()
                    .map(|message| {
                        (
                            message.device_id.into(),
                            individual_recipient_message_bundle::Message {
                                registration_id: message.registration_id,
                                payload: message.contents.serialize().to_vec(),
                                r#type: message
                                    .grpc_unsealed_message_type()
                                    .expect("checked above")
                                    .into(),
                            },
                        )
                    })
                    .collect(),
            }),
        };
        let log_safe_description = Redact(&request).to_string();

        let SendMessageAuthenticatedSenderResponse { response } =
            log_and_send("auth", &log_safe_description, || {
                service.send_message(request)
            })
            .await?
            .into_inner();

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        match response {
            send_message_authenticated_sender_response::Response::Success(()) => Ok(()),
            send_message_authenticated_sender_response::Response::MismatchedDevices(
                mismatched_devices,
            ) => Err(RequestError::Other(
                MismatchedDeviceError::try_from(mismatched_devices)
                    .map_err(RequestError::with_other)?
                    .into(),
            )),
            send_message_authenticated_sender_response::Response::ChallengeRequired(
                challenge_required,
            ) => Err(RequestError::Challenge(
                challenge_required
                    .try_into()
                    .map_err(RequestError::with_other)?,
            )),
            send_message_authenticated_sender_response::Response::DestinationNotFound(
                errors::NotFound {},
            ) => Err(RequestError::Other(UnsealedSendFailure::ServiceIdNotFound)),
        }
    }

    async fn send_sync_message(
        &self,
        timestamp: Timestamp,
        contents: &[SingleOutboundUnsealedMessage<'_>],
        urgent: bool,
    ) -> Result<(), RequestError<MismatchedDeviceError>> {
        SingleOutboundUnsealedMessage::assert_valid_unsealed_message_types(contents);

        let mut service = MessagesClient::new(self.0.service());
        let request = SendSyncMessageRequest {
            urgent,
            messages: Some(IndividualRecipientMessageBundle {
                timestamp: timestamp.epoch_millis(),
                messages: contents
                    .iter()
                    .map(|message| {
                        (
                            message.device_id.into(),
                            individual_recipient_message_bundle::Message {
                                registration_id: message.registration_id,
                                payload: message.contents.serialize().to_vec(),
                                r#type: message
                                    .grpc_unsealed_message_type()
                                    .expect("checked above")
                                    .into(),
                            },
                        )
                    })
                    .collect(),
            }),
        };
        let log_safe_description = Redact(&request).to_string();

        let SendMessageAuthenticatedSenderResponse { response } =
            log_and_send("auth", &log_safe_description, || {
                service.send_sync_message(request)
            })
            .await?
            .into_inner();

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        match response {
            send_message_authenticated_sender_response::Response::Success(()) => Ok(()),
            send_message_authenticated_sender_response::Response::MismatchedDevices(
                mismatched_devices,
            ) => Err(RequestError::Other(
                MismatchedDeviceError::try_from(mismatched_devices)
                    .map_err(RequestError::with_other)?,
            )),
            send_message_authenticated_sender_response::Response::ChallengeRequired(
                challenge_required,
            ) => Err(RequestError::Challenge(
                challenge_required
                    .try_into()
                    .map_err(RequestError::with_other)?,
            )),
            send_message_authenticated_sender_response::Response::DestinationNotFound(
                errors::NotFound {},
            ) => Err(RequestError::Unexpected {
                log_safe: "message to self produced destination_not_found".into(),
            }),
        }
    }

    async fn get_upload_form(
        &self,
        upload_length: u64,
    ) -> Result<UploadForm, RequestError<UploadTooLarge>> {
        let mut attachments_service = AttachmentsClient::new(self.0.service());
        let request = attachments::GetUploadFormRequest { upload_length };
        let log_safe_description = Redact(&request).to_string();
        let response = log_and_send("auth", &log_safe_description, || {
            attachments_service.get_upload_form(request)
        })
        .await?
        .into_inner();
        let Some(response) = response.outcome else {
            return Err(RequestError::Unexpected {
                log_safe: "Response outcome is empty".to_string(),
            });
        };
        match response {
            Outcome::UploadForm(common::UploadForm {
                cdn,
                key,
                headers,
                signed_upload_location,
            }) => Ok(UploadForm {
                cdn,
                key,
                headers: headers.into_iter().collect(),
                signed_upload_url: signed_upload_location,
            }),
            Outcome::ExceedsMaxUploadLength(errors::FailedPrecondition { description: _ }) => {
                Err(RequestError::Other(UploadTooLarge))
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

impl std::fmt::Display for Redact<SendStoryMessageRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SendStoryMessageRequest {
            destination,
            urgent,
            messages,
        }) = self;
        f.debug_struct("SendStoryMessageRequest")
            .field("timestamp", &messages.as_ref().map_or(0, |m| m.timestamp))
            .field("destination", &destination.as_ref().map(Redact))
            .field("urgent", urgent)
            .finish()
    }
}

impl std::fmt::Display for Redact<SendSealedSenderMessageRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SendSealedSenderMessageRequest {
            destination,
            ephemeral,
            urgent,
            messages,
            authorization: _,
        }) = self;
        f.debug_struct("SendSealedSenderMessageRequest")
            .field("timestamp", &messages.as_ref().map_or(0, |m| m.timestamp))
            .field("destination", &destination.as_ref().map(Redact))
            .field("ephemeral", ephemeral)
            .field("urgent", urgent)
            .finish()
    }
}

impl std::fmt::Display for Redact<SendAuthenticatedSenderMessageRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SendAuthenticatedSenderMessageRequest {
            destination,
            ephemeral,
            urgent,
            messages,
        }) = self;
        f.debug_struct("SendAuthenticatedSenderMessageRequest")
            .field("timestamp", &messages.as_ref().map_or(0, |m| m.timestamp))
            .field("destination", &destination.as_ref().map(Redact))
            .field("ephemeral", ephemeral)
            .field("urgent", urgent)
            .finish()
    }
}

impl std::fmt::Display for Redact<SendSyncMessageRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SendSyncMessageRequest { urgent, messages }) = self;
        f.debug_struct("SendSyncMessageRequest")
            .field("timestamp", &messages.as_ref().map_or(0, |m| m.timestamp))
            .field("urgent", urgent)
            .finish()
    }
}

impl std::fmt::Display for Redact<attachments::GetUploadFormRequest> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let Self(attachments::GetUploadFormRequest { upload_length }) = self;
        f.debug_struct("attachments::GetUploadFormRequest")
            .field("upload_length", upload_length)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::collections::HashMap;

    use const_str::hex;
    use futures_util::FutureExt as _;
    use libsignal_core::{Aci, Pni, ServiceId};
    use libsignal_net::infra::errors::RetryLater;
    use libsignal_net_grpc::proto::chat::attachments::get_upload_form_response;
    use libsignal_net_grpc::proto::chat::messages::ChallengeRequired as ChallengeRequiredProto;
    use libsignal_net_grpc::proto::chat::messages::send_sealed_sender_message_request::Authorization as SealedSenderAuthorization;
    use libsignal_net_grpc::proto::chat::services;
    use libsignal_protocol::{CiphertextMessage, PlaintextContent, Timestamp};
    use test_case::test_case;
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::api::messages::{AuthenticatedChatApi, UnauthenticatedChatApi as _};
    use crate::api::testutil::{SERIALIZED_GROUP_SEND_TOKEN, structurally_valid_group_send_token};
    use crate::api::{ChallengeOption, RateLimitChallenge};
    use crate::grpc::testutil::{
        GrpcOverrideRequestValidator, RequestValidator, TypedRequestValidator, err, ok, req,
        req_typed,
    };

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

    #[test_case(ok(SendMessageResponse {
        response: Some(send_message_response::Response::Success(()))
    }) => matches Ok(()))]
    #[test_case(ok(SendMessageResponse {
        response: None
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMessageResponse {
        response: Some(send_message_response::Response::DestinationNotFound(Default::default())),
    }) => matches Err(RequestError::Other(SealedSendFailure::ServiceIdNotFound)))]
    #[test_case(ok(SendMessageResponse {
        response: Some(send_message_response::Response::MismatchedDevices(
            MismatchedDevices {
                service_identifier: Some(Pni::from(PNI_UUID).into()),
                missing_devices: vec![2, 3],
                extra_devices: vec![4, 5],
                stale_devices: vec![6, 7],
            }
        )),
    }) => matches Err(RequestError::Other(SealedSendFailure::MismatchedDevices(error))) if error ==
        MismatchedDeviceError {
            account: Pni::from(PNI_UUID).into(),
            missing_devices: vec![DeviceId::new(2).unwrap(), DeviceId::new(3).unwrap()],
            extra_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
            stale_devices: vec![DeviceId::new(6).unwrap(), DeviceId::new(7).unwrap()],
        }
    )]
    #[test_case(ok(SendMessageResponse {
        response: Some(send_message_response::Response::MismatchedDevices(
            MismatchedDevices {
                service_identifier: Some(Pni::from(PNI_UUID).into()),
                missing_devices: vec![],
                extra_devices: vec![],
                stale_devices: vec![],
            }
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMessageResponse {
        response: Some(send_message_response::Response::FailedUnidentifiedAuthorization(
            errors::FailedUnidentifiedAuthorization {
                description: "too bad".to_owned(),
            },
        )),
    }) => matches Err(RequestError::Other(SealedSendFailure::Unauthorized)))]
    fn test_sealed_send(
        response: http::Response<Vec<u8>>,
    ) -> Result<(), RequestError<SealedSendFailure>> {
        let validator = GrpcOverrideRequestValidator {
            message: services::MessagesAnonymous::SendSingleRecipientMessage.into(),
            validator: TypedRequestValidator {
                expected: req_typed(
                    "/org.signal.chat.messages.MessagesAnonymous/SendSingleRecipientMessage",
                    SendSealedSenderMessageRequest {
                        destination: Some(Pni::from(PNI_UUID).into()),
                        ephemeral: false,
                        urgent: true,
                        authorization: Some(SealedSenderAuthorization::UnidentifiedAccessKey(
                            vec![0xa0; 16],
                        )),
                        messages: Some(IndividualRecipientMessageBundle {
                            timestamp: 1700000000000,
                            messages: HashMap::from_iter([
                                (
                                    2,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 22,
                                        payload: vec![1, 2, 3],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                                (
                                    3,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 33,
                                        payload: vec![4, 5, 6],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                            ]),
                        }),
                    },
                ),
                response,
            },
        };

        Unauth(&validator)
            .send_message(
                Pni::from(PNI_UUID).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[1, 2, 3]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[4, 5, 6]),
                    },
                ],
                UserBasedAuthorization::AccessKey([0xa0; 16]).into(),
                false,
                true,
            )
            .now_or_never()
            .expect("sync")
    }

    #[test]
    fn test_sealed_send_using_group_token() {
        let validator = GrpcOverrideRequestValidator {
            message: services::MessagesAnonymous::SendSingleRecipientMessage.into(),
            validator: TypedRequestValidator {
                expected: req_typed(
                    "/org.signal.chat.messages.MessagesAnonymous/SendSingleRecipientMessage",
                    SendSealedSenderMessageRequest {
                        destination: Some(Aci::from(ACI_UUID).into()),
                        ephemeral: false,
                        urgent: true,
                        authorization: Some(SealedSenderAuthorization::GroupSendToken(
                            SERIALIZED_GROUP_SEND_TOKEN.to_vec(),
                        )),
                        messages: Some(IndividualRecipientMessageBundle {
                            timestamp: 1700000000000,
                            messages: HashMap::from_iter([
                                (
                                    2,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 22,
                                        payload: vec![1, 2, 3],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                                (
                                    3,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 33,
                                        payload: vec![4, 5, 6],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                            ]),
                        }),
                    },
                ),
                response: ok(SendMessageResponse {
                    response: Some(send_message_response::Response::Success(())),
                }),
            },
        };

        Unauth(&validator)
            .send_message(
                Aci::from(ACI_UUID).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[1, 2, 3]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[4, 5, 6]),
                    },
                ],
                UserBasedAuthorization::Group(structurally_valid_group_send_token()).into(),
                false,
                true,
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test]
    fn test_sealed_send_unrestricted_access() {
        let validator = GrpcOverrideRequestValidator {
            message: services::MessagesAnonymous::SendSingleRecipientMessage.into(),
            validator: TypedRequestValidator {
                expected: req_typed(
                    "/org.signal.chat.messages.MessagesAnonymous/SendSingleRecipientMessage",
                    SendSealedSenderMessageRequest {
                        destination: Some(Aci::from(ACI_UUID).into()),
                        ephemeral: false,
                        urgent: true,
                        authorization: Some(SealedSenderAuthorization::UnrestrictedAccess(())),
                        messages: Some(IndividualRecipientMessageBundle {
                            timestamp: 1700000000000,
                            messages: HashMap::from_iter([
                                (
                                    2,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 22,
                                        payload: vec![1, 2, 3],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                                (
                                    3,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 33,
                                        payload: vec![4, 5, 6],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                            ]),
                        }),
                    },
                ),
                response: ok(SendMessageResponse {
                    response: Some(send_message_response::Response::Success(())),
                }),
            },
        };

        Unauth(&validator)
            .send_message(
                Aci::from(ACI_UUID).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[1, 2, 3]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[4, 5, 6]),
                    },
                ],
                UserBasedAuthorization::UnrestrictedUnauthenticatedAccess.into(),
                false,
                true,
            )
            .now_or_never()
            .expect("sync")
            .expect("success");
    }

    #[test]
    fn test_story_single_recipient() {
        let validator = GrpcOverrideRequestValidator {
            message: services::MessagesAnonymous::SendSingleRecipientMessage.into(),
            validator: TypedRequestValidator {
                expected: req_typed(
                    "/org.signal.chat.messages.MessagesAnonymous/SendStory",
                    SendStoryMessageRequest {
                        destination: Some(Pni::from(PNI_UUID).into()),
                        urgent: true,
                        messages: Some(IndividualRecipientMessageBundle {
                            timestamp: 1700000000000,
                            messages: HashMap::from_iter([
                                (
                                    2,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 22,
                                        payload: vec![1, 2, 3],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                                (
                                    3,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 33,
                                        payload: vec![4, 5, 6],
                                        r#type: SendMessageType::UnidentifiedSender.into(),
                                    },
                                ),
                            ]),
                        }),
                    },
                ),
                response: ok(SendMessageResponse {
                    response: Some(send_message_response::Response::Success(())),
                }),
            },
        };

        Unauth(&validator)
            .send_message(
                Pni::from(PNI_UUID).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[1, 2, 3]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[4, 5, 6]),
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

    #[test]
    #[should_panic(expected = "online-only")]
    fn ephemeral_story_is_not_allowed_single_recipient() {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.messages.MessagesAnonymous/SendStory",
                SendMultiRecipientStoryRequest::default(),
            ),
            response: err(tonic::Code::FailedPrecondition),
        };

        _ = Unauth(&validator)
            .send_message(
                Pni::from(PNI_UUID).into(),
                Timestamp::from_epoch_millis(1700000000000),
                &[
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(2).expect("valid"),
                        registration_id: 22,
                        contents: Cow::Borrowed(&[1, 2, 3]),
                    },
                    SingleOutboundSealedSenderMessage {
                        device_id: DeviceId::new(3).expect("valid"),
                        registration_id: 33,
                        contents: Cow::Borrowed(&[4, 5, 6]),
                    },
                ],
                UserBasedSendAuthorization::Story,
                true,
                true,
            )
            .now_or_never()
            .expect("sync");
    }

    #[test]
    fn test_attachment_get_upload_form_too_large() {
        let validator = GrpcOverrideRequestValidator {
            message: services::Attachments::GetUploadForm.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.attachments.Attachments/GetUploadForm",
                    attachments::GetUploadFormRequest {
                        upload_length: 12345,
                    },
                ),
                response: ok(attachments::GetUploadFormResponse {
                    outcome: Some(get_upload_form_response::Outcome::ExceedsMaxUploadLength(
                        errors::FailedPrecondition {
                            description: Default::default(),
                        },
                    )),
                }),
            },
        };
        let err = Auth(&validator)
            .get_upload_form(12345)
            .now_or_never()
            .expect("sync")
            .expect_err("failure");
        assert!(
            matches!(err, RequestError::Other(UploadTooLarge)),
            "{err:?}"
        );
    }

    #[test]
    fn test_attachment_get_upload_form() {
        let validator = GrpcOverrideRequestValidator {
            message: services::Attachments::GetUploadForm.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.attachments.Attachments/GetUploadForm",
                    attachments::GetUploadFormRequest {
                        upload_length: 12345,
                    },
                ),
                response: ok(attachments::GetUploadFormResponse {
                    outcome: Some(get_upload_form_response::Outcome::UploadForm(
                        common::UploadForm {
                            cdn: 2,
                            key: "my key".to_string(),
                            headers: HashMap::from_iter([
                                ("one".to_string(), "val1".to_string()),
                                ("two".to_string(), "val2".to_string()),
                            ]),
                            signed_upload_location: "location".to_string(),
                        },
                    )),
                }),
            },
        };
        let mut upload_form = Auth(&validator)
            .get_upload_form(12345)
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

    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::Success(()))
    }) => matches Ok(()))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: None
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::DestinationNotFound(Default::default())),
    }) => matches Err(RequestError::Other(UnsealedSendFailure::ServiceIdNotFound)))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::MismatchedDevices(
            MismatchedDevices {
                service_identifier: Some(Pni::from(PNI_UUID).into()),
                missing_devices: vec![2, 3],
                extra_devices: vec![4, 5],
                stale_devices: vec![6, 7],
            }
        )),
    }) => matches Err(RequestError::Other(UnsealedSendFailure::MismatchedDevices(error))) if error ==
        MismatchedDeviceError {
            account: Pni::from(PNI_UUID).into(),
            missing_devices: vec![DeviceId::new(2).unwrap(), DeviceId::new(3).unwrap()],
            extra_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
            stale_devices: vec![DeviceId::new(6).unwrap(), DeviceId::new(7).unwrap()],
        }
    )]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::MismatchedDevices(
            MismatchedDevices {
                service_identifier: Some(Pni::from(PNI_UUID).into()),
                missing_devices: vec![],
                extra_devices: vec![],
                stale_devices: vec![],
            }
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::ChallengeRequired(
            ChallengeRequiredProto {
                token: "abc".into(),
                challenge_options: vec![2, 1],
                retry_after_seconds: Some(42),
            }
        )),
    }) => matches Err(RequestError::Challenge(RateLimitChallenge {
        token, options, retry_later: Some(RetryLater { retry_after_seconds: 42 })
    })) if token == "abc" && options == vec![ChallengeOption::PushChallenge, ChallengeOption::Captcha])]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::ChallengeRequired(
            ChallengeRequiredProto {
                token: "abc".into(),
                challenge_options: vec![5000],
                retry_after_seconds: Some(42),
            }
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    fn test_unsealed_send(
        response: http::Response<Vec<u8>>,
    ) -> Result<(), RequestError<UnsealedSendFailure>> {
        let validator = GrpcOverrideRequestValidator {
            message: services::Messages::SendMessage.into(),
            // We have to use TypedRequestValidator because `messages` is a `map`.
            validator: TypedRequestValidator {
                expected: req_typed(
                    "/org.signal.chat.messages.Messages/SendMessage",
                    SendAuthenticatedSenderMessageRequest {
                        destination: Some(Pni::from(PNI_UUID).into()),
                        ephemeral: false,
                        urgent: true,
                        messages: Some(IndividualRecipientMessageBundle {
                            timestamp: 1700000000000,
                            messages: HashMap::from_iter([
                                (
                                    2,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 22,
                                        payload: hex!("C001020380").to_vec(),
                                        r#type: SendMessageType::PlaintextContent.into(),
                                    },
                                ),
                                (
                                    3,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 33,
                                        payload: hex!("C004050680").to_vec(),
                                        r#type: SendMessageType::PlaintextContent.into(),
                                    },
                                ),
                            ]),
                        }),
                    },
                ),
                response,
            },
        };

        Auth(validator)
            .send_message(
                Pni::from(PNI_UUID).into(),
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

    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::Success(()))
    }) => matches Ok(()))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: None
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::DestinationNotFound(Default::default())),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::MismatchedDevices(
            MismatchedDevices {
                service_identifier: Some(Pni::from(PNI_UUID).into()),
                missing_devices: vec![2, 3],
                extra_devices: vec![4, 5],
                stale_devices: vec![6, 7],
            }
        )),
    }) => matches Err(RequestError::Other(error)) if error ==
        MismatchedDeviceError {
            account: Pni::from(PNI_UUID).into(),
            missing_devices: vec![DeviceId::new(2).unwrap(), DeviceId::new(3).unwrap()],
            extra_devices: vec![DeviceId::new(4).unwrap(), DeviceId::new(5).unwrap()],
            stale_devices: vec![DeviceId::new(6).unwrap(), DeviceId::new(7).unwrap()],
        }
    )]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::MismatchedDevices(
            MismatchedDevices {
                service_identifier: Some(Pni::from(PNI_UUID).into()),
                missing_devices: vec![],
                extra_devices: vec![],
                stale_devices: vec![],
            }
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::ChallengeRequired(
            ChallengeRequiredProto {
                token: "abc".into(),
                challenge_options: vec![2, 1],
                retry_after_seconds: Some(42),
            }
        )),
    }) => matches Err(RequestError::Challenge(RateLimitChallenge {
        token, options, retry_later: Some(RetryLater { retry_after_seconds: 42 })
    })) if token == "abc" && options == vec![ChallengeOption::PushChallenge, ChallengeOption::Captcha])]
    #[test_case(ok(SendMessageAuthenticatedSenderResponse {
        response: Some(send_message_authenticated_sender_response::Response::ChallengeRequired(
            ChallengeRequiredProto {
                token: "abc".into(),
                challenge_options: vec![5000],
                retry_after_seconds: Some(42),
            }
        )),
    }) => matches Err(RequestError::Unexpected { .. }))]
    fn test_sync_send(
        response: http::Response<Vec<u8>>,
    ) -> Result<(), RequestError<MismatchedDeviceError>> {
        let validator = GrpcOverrideRequestValidator {
            message: services::Messages::SendMessage.into(),
            // We have to use TypedRequestValidator because `messages` is a `map`.
            validator: TypedRequestValidator {
                expected: req_typed(
                    "/org.signal.chat.messages.Messages/SendSyncMessage",
                    SendSyncMessageRequest {
                        urgent: true,
                        messages: Some(IndividualRecipientMessageBundle {
                            timestamp: 1700000000000,
                            messages: HashMap::from_iter([
                                (
                                    2,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 22,
                                        payload: hex!("C001020380").to_vec(),
                                        r#type: SendMessageType::PlaintextContent.into(),
                                    },
                                ),
                                (
                                    3,
                                    individual_recipient_message_bundle::Message {
                                        registration_id: 33,
                                        payload: hex!("C004050680").to_vec(),
                                        r#type: SendMessageType::PlaintextContent.into(),
                                    },
                                ),
                            ]),
                        }),
                    },
                ),
                response,
            },
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
}
