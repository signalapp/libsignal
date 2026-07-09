//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use futures_util::Stream;
use libsignal_account_keys::{
    MEDIA_ENCRYPTION_AES_KEY_LEN, MEDIA_ENCRYPTION_HMAC_KEY_LEN, MEDIA_ENCRYPTION_KEY_LEN,
    MEDIA_ID_LEN,
};
use libsignal_net_grpc::proto::chat::backup::backups_anonymous_client::BackupsAnonymousClient;
use libsignal_net_grpc::proto::chat::backup::get_upload_form_request::{
    MediaUploadType, MessagesUploadType, UploadType,
};
use libsignal_net_grpc::proto::chat::backup::{
    BackupStreamClosed, CopyMediaRequest, CopyMediaResponse, DeleteAllRequest, DeleteAllResponse,
    DeleteMediaItem, DeleteMediaRequest, DeleteMediaResponse, GetCdnCredentialsRequest,
    GetCdnCredentialsResponse, GetSvrBCredentialsRequest, GetSvrBCredentialsResponse,
    GetUploadFormRequest, GetUploadFormResponse, RefreshRequest, RefreshResponse,
    SetPublicKeyRequest, SetPublicKeyResponse, SignedPresentation, backup_stream_closed,
    copy_media_response, delete_all_response, get_cdn_credentials_response,
    get_svr_b_credentials_response, get_upload_form_response, refresh_response,
    set_public_key_response,
};
use libsignal_net_grpc::proto::chat::common;
use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, FailedZkAuthentication};

use super::{
    GrpcServiceProvider, OverGrpc, StreamResult, log_and_send,
    send_request_with_streaming_response, single_matching_details,
};
use crate::api::backups::{
    BackupAuth, BackupAuthCredentialRejected, BackupAuthPresentation, CdnCredentials,
    GetUploadFormFailure,
};
use crate::api::{RequestError, Unauth, UploadForm};
use crate::logging::{DebugByCalling, Redact};

impl From<BackupAuthPresentation> for SignedPresentation {
    fn from(value: BackupAuthPresentation) -> Self {
        Self {
            presentation: value.serialized_presentation,
            presentation_signature: value.signature,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CopyBackupMediaItem {
    pub source_attachment_cdn: u32,
    pub source_key: String,
    pub object_length: u64,
    pub media_id: [u8; MEDIA_ID_LEN],
    // A combined AES + HMAC key, because that's what comes out of `BackupKey::derive_media_encryption_key_data`.
    pub encryption_key: [u8; MEDIA_ENCRYPTION_KEY_LEN],
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct CopyBackupMediaOutcome {
    pub media_id: [u8; MEDIA_ID_LEN],
    pub cdn_or_failure: Result<u32, CopyBackupMediaFailure>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum CopyBackupMediaFailure {
    SourceNotFound,
    WrongSourceLength,
    OutOfSpace,
}

impl From<CopyBackupMediaItem> for libsignal_net_grpc::proto::chat::backup::CopyMediaItem {
    fn from(value: CopyBackupMediaItem) -> Self {
        let CopyBackupMediaItem {
            source_attachment_cdn,
            source_key,
            object_length,
            media_id,
            encryption_key,
        } = value;
        let (hmac_key, aes_key) = encryption_key.split_at(MEDIA_ENCRYPTION_HMAC_KEY_LEN);
        debug_assert_eq!(aes_key.len(), MEDIA_ENCRYPTION_AES_KEY_LEN);
        Self {
            source_attachment_cdn,
            source_key,
            object_length,
            media_id: media_id.to_vec(),
            hmac_key: hmac_key.to_vec(),
            encryption_key: aes_key.to_vec(),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct DeleteBackupMediaItem {
    pub media_id: [u8; MEDIA_ID_LEN],
    pub cdn: u32,
}

impl DeleteBackupMediaItem {
    fn to_proto(&self) -> DeleteMediaItem {
        let Self { media_id, cdn } = *self;
        DeleteMediaItem {
            cdn,
            media_id: media_id.to_vec(),
        }
    }
}

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::backups::UnauthenticatedChatApi<OverGrpc> for Unauth<T> {
    async fn get_upload_form(
        &self,
        auth: &BackupAuth,
        upload_size: u64,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let mut backup_service = BackupsAnonymousClient::new(self.0.service());

        let auth = auth.present(rng)?;

        let request = GetUploadFormRequest {
            signed_presentation: Some(auth.into()),
            upload_length: upload_size,
            upload_type: Some(UploadType::Messages(MessagesUploadType {})),
        };
        let log_safe_description = Redact(&request).to_string();
        let response: GetUploadFormResponse = log_and_send("unauth", &log_safe_description, || {
            backup_service.get_upload_form(request)
        })
        .await?
        .into_inner();

        response.try_into()
    }

    async fn get_media_upload_form(
        &self,
        auth: &BackupAuth,
        upload_size: u64,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let mut backup_service = BackupsAnonymousClient::new(self.0.service());

        let auth = auth.present(rng)?;

        let request = GetUploadFormRequest {
            signed_presentation: Some(auth.into()),
            upload_length: upload_size,
            upload_type: Some(UploadType::Media(MediaUploadType {})),
        };
        let log_safe_description = Redact(&request).to_string();
        let response: GetUploadFormResponse = log_and_send("unauth", &log_safe_description, || {
            backup_service.get_upload_form(request)
        })
        .await?
        .into_inner();

        response.try_into()
    }
}

impl<T: GrpcServiceProvider> Unauth<T> {
    pub async fn set_backup_public_key(
        &self,
        auth: &BackupAuth<'_>,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<(), RequestError<BackupAuthCredentialRejected>> {
        let mut backup_service = BackupsAnonymousClient::new(self.0.service());

        let public_key = auth.signing_public_key();
        let auth = auth.present(rng)?;

        let request = SetPublicKeyRequest {
            signed_presentation: Some(auth.into()),
            public_key: public_key.serialize().into_vec(),
        };
        let log_safe_description = Redact(&request).to_string();
        let response: SetPublicKeyResponse = log_and_send("unauth", &log_safe_description, || {
            backup_service.set_public_key(request)
        })
        .await?
        .into_inner();

        let response = response.response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;
        match response {
            set_public_key_response::Response::Success(_) => Ok(()),
            set_public_key_response::Response::FailedAuthentication(FailedZkAuthentication {
                description,
            }) => {
                log::warn!("failed zk auth: {description}");
                Err(RequestError::Other(BackupAuthCredentialRejected))
            }
        }
    }

    pub async fn get_backup_cdn_credentials(
        &self,
        auth: &BackupAuth<'_>,
        cdn: u32,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<CdnCredentials, RequestError<BackupAuthCredentialRejected>> {
        let mut backup_service = BackupsAnonymousClient::new(self.0.service());

        let auth = auth.present(rng)?;

        let request = GetCdnCredentialsRequest {
            signed_presentation: Some(auth.into()),
            cdn,
        };
        let log_safe_description = Redact(&request).to_string();
        let response: GetCdnCredentialsResponse =
            log_and_send("unauth", &log_safe_description, || {
                backup_service.get_cdn_credentials(request)
            })
            .await?
            .into_inner();

        let response = response.response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;
        match response {
            get_cdn_credentials_response::Response::CdnCredentials(
                get_cdn_credentials_response::CdnCredentials { headers },
            ) => Ok(CdnCredentials {
                headers: headers.into_iter().collect(),
            }),
            get_cdn_credentials_response::Response::FailedAuthentication(
                FailedZkAuthentication { description },
            ) => {
                log::warn!("failed zk auth: {description}");
                Err(RequestError::Other(BackupAuthCredentialRejected))
            }
        }
    }

    pub async fn get_backup_svrb_credentials(
        &self,
        auth: &BackupAuth<'_>,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<libsignal_net::auth::Auth, RequestError<BackupAuthCredentialRejected>> {
        let mut backup_service = BackupsAnonymousClient::new(self.0.service());

        let auth = auth.present(rng)?;

        let request = GetSvrBCredentialsRequest {
            signed_presentation: Some(auth.into()),
        };
        let log_safe_description = Redact(&request).to_string();
        let response: GetSvrBCredentialsResponse =
            log_and_send("unauth", &log_safe_description, || {
                backup_service.get_svr_b_credentials(request)
            })
            .await?
            .into_inner();

        let response = response.response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;
        match response {
            get_svr_b_credentials_response::Response::SvrbCredentials(
                get_svr_b_credentials_response::SvrBCredentials { username, password },
            ) => Ok(libsignal_net::auth::Auth { username, password }),
            get_svr_b_credentials_response::Response::FailedAuthentication(
                FailedZkAuthentication { description },
            ) => {
                log::warn!("failed zk auth: {description}");
                Err(RequestError::Other(BackupAuthCredentialRejected))
            }
        }
    }

    pub async fn refresh_backup(
        &self,
        auth: &BackupAuth<'_>,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<(), RequestError<BackupAuthCredentialRejected>> {
        let mut backup_service = BackupsAnonymousClient::new(self.0.service());

        let auth = auth.present(rng)?;

        let request = RefreshRequest {
            signed_presentation: Some(auth.into()),
        };
        let log_safe_description = Redact(&request).to_string();
        let response: RefreshResponse = log_and_send("unauth", &log_safe_description, || {
            backup_service.refresh(request)
        })
        .await?
        .into_inner();

        let response = response.response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;
        match response {
            refresh_response::Response::Success(_) => Ok(()),
            refresh_response::Response::FailedAuthentication(FailedZkAuthentication {
                description,
            }) => {
                log::warn!("failed zk auth: {description}");
                Err(RequestError::Other(BackupAuthCredentialRejected))
            }
        }
    }

    pub async fn backup_delete_all(
        &self,
        auth: &BackupAuth<'_>,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<(), RequestError<BackupAuthCredentialRejected>> {
        let mut backup_service = BackupsAnonymousClient::new(self.0.service());

        let auth = auth.present(rng)?;

        let request = DeleteAllRequest {
            signed_presentation: Some(auth.into()),
        };
        let log_safe_description = Redact(&request).to_string();
        let response: DeleteAllResponse = log_and_send("unauth", &log_safe_description, || {
            backup_service.delete_all(request)
        })
        .await?
        .into_inner();

        let response = response.response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;
        match response {
            delete_all_response::Response::Success(_) => Ok(()),
            delete_all_response::Response::FailedAuthentication(FailedZkAuthentication {
                description,
            }) => {
                log::warn!("failed zk auth: {description}");
                Err(RequestError::Other(BackupAuthCredentialRejected))
            }
        }
    }

    pub fn copy_backup_media(
        &self,
        auth: &BackupAuth<'_>,
        items: Vec<CopyBackupMediaItem>,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> impl Stream<Item = StreamResult<CopyBackupMediaOutcome, BackupAuthCredentialRejected>> + 'static
    where
        T::Service: 'static,
    {
        send_request_with_streaming_response(
            "unauth",
            self.0.service(),
            || {
                let auth = auth.present(rng)?;
                Ok(CopyMediaRequest {
                    signed_presentation: Some(auth.into()),
                    items: items.into_iter().map(Into::into).collect(),
                })
            },
            |service, request| async move {
                BackupsAnonymousClient::new(service)
                    .copy_media(request)
                    .await
            },
            |CopyMediaResponse { media_id, response }| {
                let media_id = media_id[..]
                    .try_into()
                    .map_err(|_| RequestError::Unexpected {
                        log_safe: format!("malformed media id ({} bytes)", media_id.len()),
                    })?;

                let response = response.ok_or_else(|| RequestError::Unexpected {
                    log_safe: "missing response".to_owned(),
                })?;

                let cdn_or_failure = match response {
                    copy_media_response::Response::Success(copy_media_response::CopySuccess {
                        cdn,
                    }) => Ok(cdn),
                    copy_media_response::Response::SourceNotFound(
                        copy_media_response::SourceNotFound {},
                    ) => Err(CopyBackupMediaFailure::SourceNotFound),
                    copy_media_response::Response::WrongSourceLength(
                        copy_media_response::WrongSourceLength {},
                    ) => Err(CopyBackupMediaFailure::WrongSourceLength),
                    copy_media_response::Response::OutOfSpace(
                        copy_media_response::OutOfSpace {},
                    ) => Err(CopyBackupMediaFailure::OutOfSpace),
                };
                Ok(CopyBackupMediaOutcome {
                    media_id,
                    cdn_or_failure,
                })
            },
            |status| {
                let closure = single_matching_details::<BackupStreamClosed>(&status.details)
                    .ok_or_else(|| RequestError::Unexpected {
                        log_safe: "stream closed with no reason".to_owned(),
                    })?;
                let reason = closure.reason.ok_or_else(|| RequestError::Unexpected {
                    log_safe: "missing reason in BackupStreamClosed".to_owned(),
                })?;
                match reason {
                    backup_stream_closed::Reason::FailedAuthentication(
                        FailedZkAuthentication { description },
                    ) => {
                        log::warn!("failed zk auth: {description}");
                        Err(RequestError::Other(BackupAuthCredentialRejected))
                    }
                }
            },
        )
    }

    pub fn delete_backup_media(
        &self,
        auth: &BackupAuth<'_>,
        items: &[DeleteBackupMediaItem],
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> impl Stream<Item = StreamResult<DeleteBackupMediaItem, BackupAuthCredentialRejected>> + 'static
    where
        T::Service: 'static,
    {
        send_request_with_streaming_response(
            "unauth",
            self.0.service(),
            || {
                let auth = auth.present(rng)?;
                Ok(DeleteMediaRequest {
                    signed_presentation: Some(auth.into()),
                    items: items.iter().map(|item| item.to_proto()).collect(),
                })
            },
            |service, request| async move {
                BackupsAnonymousClient::new(service)
                    .delete_media(request)
                    .await
            },
            |DeleteMediaResponse { deleted_item }| {
                let DeleteMediaItem { cdn, media_id } =
                    deleted_item.ok_or_else(|| RequestError::Unexpected {
                        log_safe: "missing deleted_item".to_owned(),
                    })?;
                let media_id = media_id[..]
                    .try_into()
                    .map_err(|_| RequestError::Unexpected {
                        log_safe: format!("malformed media id ({} bytes)", media_id.len()),
                    })?;
                Ok(DeleteBackupMediaItem { cdn, media_id })
            },
            |status| {
                let closure = single_matching_details::<BackupStreamClosed>(&status.details)
                    .ok_or_else(|| RequestError::Unexpected {
                        log_safe: "stream closed with no reason".to_owned(),
                    })?;
                let reason = closure.reason.ok_or_else(|| RequestError::Unexpected {
                    log_safe: "missing reason in BackupStreamClosed".to_owned(),
                })?;
                match reason {
                    backup_stream_closed::Reason::FailedAuthentication(
                        FailedZkAuthentication { description },
                    ) => {
                        log::warn!("failed zk auth: {description}");
                        Err(RequestError::Other(BackupAuthCredentialRejected))
                    }
                }
            },
        )
    }
}

// Factored out so it can be shared between `get_upload_form` and `get_media_upload_form`.
impl TryFrom<GetUploadFormResponse> for UploadForm {
    type Error = RequestError<GetUploadFormFailure>;

    fn try_from(value: GetUploadFormResponse) -> Result<Self, Self::Error> {
        let response = value.response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        match response {
            get_upload_form_response::Response::UploadForm(common::UploadForm {
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

            get_upload_form_response::Response::FailedAuthentication(FailedZkAuthentication {
                description,
            }) => {
                log::warn!("failed zk auth: {description}");
                Err(RequestError::Other(GetUploadFormFailure::Unauthorized))
            }

            get_upload_form_response::Response::ExceedsMaxUploadLength(FailedPrecondition {
                description,
            }) => {
                log::warn!("exceeded max upload length: {description}");
                Err(RequestError::Other(GetUploadFormFailure::UploadTooLarge))
            }
        }
    }
}

impl std::fmt::Display for Redact<GetUploadFormRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GetUploadFormRequest {
            // Omit the presentation, in line with WS logs only showing the URL and not headers.
            signed_presentation: _,
            upload_length,
            upload_type,
        }) = self;

        f.debug_struct("GetUploadFormRequest")
            .field(
                "type",
                &DebugByCalling(|f| match upload_type {
                    Some(UploadType::Messages(MessagesUploadType {})) => {
                        f.debug_struct("Messages").finish()
                    }
                    Some(UploadType::Media(MediaUploadType {})) => f.debug_struct("Media").finish(),
                    None => f.write_str("<none>"),
                }),
            )
            .field("upload_length", upload_length)
            .finish()
    }
}

impl std::fmt::Display for Redact<SetPublicKeyRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetPublicKeyRequest {
            // Omit the presentation, in line with WS logs only showing the URL and not headers.
            signed_presentation: _,
            public_key,
        }) = self;

        f.debug_struct("SetPublicKeyRequest")
            .field("public_key_type", public_key.first().unwrap_or(&0))
            .finish()
    }
}

impl std::fmt::Display for Redact<GetCdnCredentialsRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GetCdnCredentialsRequest {
            // Omit the presentation, in line with WS logs only showing the URL and not headers.
            signed_presentation: _,
            cdn,
        }) = self;

        f.debug_struct("GetCdnCredentialsRequest")
            .field("cdn", cdn)
            .finish()
    }
}

impl std::fmt::Display for Redact<CopyMediaRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(CopyMediaRequest {
            signed_presentation: _,
            items,
        }) = self;

        f.debug_struct("CopyMediaRequest")
            .field("items", &items.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<DeleteMediaRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(DeleteMediaRequest {
            signed_presentation: _,
            items,
        }) = self;

        f.debug_struct("DeleteMediaRequest")
            .field("items", &items.len())
            .finish()
    }
}

macro_rules! redact_no_arg_backup_request {
    ($name:ident) => {
        impl std::fmt::Display for Redact<$name> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let Self($name {
                    // Omit the presentation, in line with WS logs only showing the URL and not headers.
                    signed_presentation: _,
                }) = self;

                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

redact_no_arg_backup_request!(GetSvrBCredentialsRequest);
redact_no_arg_backup_request!(RefreshRequest);
redact_no_arg_backup_request!(DeleteAllRequest);

// Not cfg(test) so it can be accessed via bridging tests.
pub mod test_cases {
    use libsignal_net::chat::fake::BodyWithTrailers;
    use libsignal_net_grpc::proto::chat::backup::CopyMediaItem;

    use super::*;
    use crate::grpc::GrpcTestCase;
    use crate::grpc::test_case_util::{status_for_server_side_error, stream};

    #[derive(Debug)]
    pub enum CopyBackupMediaOut {
        Item(CopyBackupMediaOutcome),
        InvalidDataInStream,
        CredentialRejected,
        CredentialRejectedWithoutAppropriateServerInfo,
    }

    #[allow(clippy::type_complexity)]
    pub fn copy_media_test_cases() -> Vec<
        GrpcTestCase<
            Vec<CopyBackupMediaItem>,
            CopyMediaRequest,
            http::Response<BodyWithTrailers>,
            Vec<CopyBackupMediaOut>,
        >,
    > {
        let method = "/org.signal.chat.backup.BackupsAnonymous/CopyMedia";
        let request = vec![
            CopyBackupMediaItem {
                source_attachment_cdn: 1,
                source_key: "key1".to_owned(),
                object_length: 111,
                media_id: [1; MEDIA_ID_LEN],
                encryption_key: *const_str::concat_bytes!([b'A'; 32], [b'B'; 32]),
            },
            CopyBackupMediaItem {
                source_attachment_cdn: 2,
                source_key: "key2".to_owned(),
                object_length: 222,
                media_id: [2; MEDIA_ID_LEN],
                encryption_key: *const_str::concat_bytes!([b'C'; 32], [b'D'; 32]),
            },
        ];
        let request_grpc = CopyMediaRequest {
            signed_presentation: Some(SignedPresentation {
                presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
            }),
            items: vec![
                CopyMediaItem {
                    source_attachment_cdn: 1,
                    source_key: "key1".to_owned(),
                    object_length: 111,
                    media_id: vec![1; MEDIA_ID_LEN],
                    hmac_key: vec![b'A'; MEDIA_ENCRYPTION_HMAC_KEY_LEN],
                    encryption_key: vec![b'B'; MEDIA_ENCRYPTION_AES_KEY_LEN],
                },
                CopyMediaItem {
                    source_attachment_cdn: 2,
                    source_key: "key2".to_owned(),
                    object_length: 222,
                    media_id: vec![2; MEDIA_ID_LEN],
                    hmac_key: vec![b'C'; MEDIA_ENCRYPTION_HMAC_KEY_LEN],
                    encryption_key: vec![b'D'; MEDIA_ENCRYPTION_AES_KEY_LEN],
                },
            ],
        };
        vec![
            GrpcTestCase {
                name: "empty".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(Vec::<CopyMediaResponse>::new(), None),
                response: vec![],
            },
            GrpcTestCase {
                name: "possible outcomes".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    vec![
                        CopyMediaResponse {
                            media_id: vec![1; MEDIA_ID_LEN],
                            response: Some(copy_media_response::Response::Success(
                                copy_media_response::CopySuccess { cdn: 5 },
                            )),
                        },
                        CopyMediaResponse {
                            media_id: vec![2; MEDIA_ID_LEN],
                            response: Some(copy_media_response::Response::SourceNotFound(
                                Default::default(),
                            )),
                        },
                        CopyMediaResponse {
                            media_id: vec![3; MEDIA_ID_LEN],
                            response: Some(copy_media_response::Response::WrongSourceLength(
                                Default::default(),
                            )),
                        },
                        CopyMediaResponse {
                            media_id: vec![4; MEDIA_ID_LEN],
                            response: Some(copy_media_response::Response::OutOfSpace(
                                Default::default(),
                            )),
                        },
                    ],
                    None,
                ),
                response: vec![
                    CopyBackupMediaOut::Item(CopyBackupMediaOutcome {
                        media_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                        cdn_or_failure: Ok(5),
                    }),
                    CopyBackupMediaOut::Item(CopyBackupMediaOutcome {
                        media_id: [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
                        cdn_or_failure: Err(CopyBackupMediaFailure::SourceNotFound),
                    }),
                    CopyBackupMediaOut::Item(CopyBackupMediaOutcome {
                        media_id: [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
                        cdn_or_failure: Err(CopyBackupMediaFailure::WrongSourceLength),
                    }),
                    CopyBackupMediaOut::Item(CopyBackupMediaOutcome {
                        media_id: [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
                        cdn_or_failure: Err(CopyBackupMediaFailure::OutOfSpace),
                    }),
                ],
            },
            GrpcTestCase {
                name: "malformed item".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    vec![
                        CopyMediaResponse {
                            media_id: vec![1; MEDIA_ID_LEN],
                            response: Some(copy_media_response::Response::Success(
                                copy_media_response::CopySuccess { cdn: 5 },
                            )),
                        },
                        CopyMediaResponse {
                            media_id: vec![2; 1],
                            response: Some(copy_media_response::Response::Success(
                                copy_media_response::CopySuccess { cdn: 5 },
                            )),
                        },
                        CopyMediaResponse {
                            media_id: vec![3; MEDIA_ID_LEN],
                            response: Some(copy_media_response::Response::Success(
                                copy_media_response::CopySuccess { cdn: 5 },
                            )),
                        },
                    ],
                    None,
                ),
                response: vec![
                    CopyBackupMediaOut::Item(CopyBackupMediaOutcome {
                        media_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                        cdn_or_failure: Ok(5),
                    }),
                    CopyBackupMediaOut::InvalidDataInStream,
                ],
            },
            GrpcTestCase {
                name: "credential rejected".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    Vec::<CopyMediaResponse>::new(),
                    Some(backup_stream_unauthorized(true)),
                ),
                response: vec![CopyBackupMediaOut::CredentialRejected],
            },
            GrpcTestCase {
                name: "credential rejected without appropriate server info".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    Vec::<CopyMediaResponse>::new(),
                    Some(backup_stream_unauthorized(false)),
                ),
                response: vec![CopyBackupMediaOut::CredentialRejectedWithoutAppropriateServerInfo],
            },
        ]
    }

    #[derive(Debug)]
    pub enum DeleteBackupMediaOut {
        Item(DeleteBackupMediaItem),
        InvalidDataInStream,
        CredentialRejected,
        CredentialRejectedWithoutAppropriateServerInfo,
    }

    #[allow(clippy::type_complexity)]
    pub fn delete_media_test_cases() -> Vec<
        GrpcTestCase<
            Vec<DeleteBackupMediaItem>,
            DeleteMediaRequest,
            http::Response<BodyWithTrailers>,
            Vec<DeleteBackupMediaOut>,
        >,
    > {
        let method = "/org.signal.chat.backup.BackupsAnonymous/DeleteMedia";
        let request = vec![
            DeleteBackupMediaItem {
                media_id: [1; MEDIA_ID_LEN],
                cdn: 1,
            },
            DeleteBackupMediaItem {
                media_id: [2; MEDIA_ID_LEN],
                cdn: 2,
            },
        ];
        let request_grpc = DeleteMediaRequest {
            signed_presentation: Some(SignedPresentation {
                presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
            }),
            items: vec![
                DeleteMediaItem {
                    cdn: 1,
                    media_id: vec![1; MEDIA_ID_LEN],
                },
                DeleteMediaItem {
                    cdn: 2,
                    media_id: vec![2; MEDIA_ID_LEN],
                },
            ],
        };
        vec![
            GrpcTestCase {
                name: "empty".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(Vec::<DeleteMediaResponse>::new(), None),
                response: vec![],
            },
            GrpcTestCase {
                name: "possible outcomes".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    vec![
                        DeleteMediaResponse {
                            deleted_item: Some(DeleteMediaItem {
                                cdn: 1,
                                media_id: vec![1; MEDIA_ID_LEN],
                            }),
                        },
                        DeleteMediaResponse {
                            deleted_item: Some(DeleteMediaItem {
                                cdn: 2,
                                media_id: vec![2; MEDIA_ID_LEN],
                            }),
                        },
                    ],
                    None,
                ),
                response: vec![
                    DeleteBackupMediaOut::Item(DeleteBackupMediaItem {
                        cdn: 1,
                        media_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                    }),
                    DeleteBackupMediaOut::Item(DeleteBackupMediaItem {
                        cdn: 2,
                        media_id: [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
                    }),
                ],
            },
            GrpcTestCase {
                name: "malformed item".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    vec![
                        DeleteMediaResponse {
                            deleted_item: Some(DeleteMediaItem {
                                cdn: 1,
                                media_id: vec![1; MEDIA_ID_LEN],
                            }),
                        },
                        DeleteMediaResponse {
                            deleted_item: Some(DeleteMediaItem {
                                cdn: 2,
                                media_id: vec![2; 1],
                            }),
                        },
                        DeleteMediaResponse {
                            deleted_item: Some(DeleteMediaItem {
                                cdn: 3,
                                media_id: vec![3; MEDIA_ID_LEN],
                            }),
                        },
                    ],
                    None,
                ),
                response: vec![
                    DeleteBackupMediaOut::Item(DeleteBackupMediaItem {
                        cdn: 1,
                        media_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                    }),
                    DeleteBackupMediaOut::InvalidDataInStream,
                ],
            },
            GrpcTestCase {
                name: "credential rejected".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    Vec::<DeleteMediaResponse>::new(),
                    Some(backup_stream_unauthorized(true)),
                ),
                response: vec![DeleteBackupMediaOut::CredentialRejected],
            },
            GrpcTestCase {
                name: "credential rejected without appropriate server info".to_owned(),
                method: method.to_owned(),
                request: request.clone(),
                request_grpc: request_grpc.clone(),
                response_grpc: stream(
                    Vec::<DeleteMediaResponse>::new(),
                    Some(backup_stream_unauthorized(false)),
                ),
                response: vec![
                    DeleteBackupMediaOut::CredentialRejectedWithoutAppropriateServerInfo,
                ],
            },
        ]
    }

    fn backup_stream_unauthorized(include_stream_closed_info: bool) -> tonic::Status {
        let backup_info = if include_stream_closed_info {
            vec![BackupStreamClosed {
                reason: Some(backup_stream_closed::Reason::FailedAuthentication(
                    FailedZkAuthentication {
                        description: "bad!".to_owned(),
                    },
                )),
            }]
        } else {
            vec![]
        };
        status_for_server_side_error(tonic::Code::Aborted, "STREAM_CLOSED", backup_info)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::fmt::Debug;

    use assert_matches::assert_matches;
    use futures_util::FutureExt as _;
    use libsignal_net::chat::fake::BodyWithTrailers;
    use libsignal_net_grpc::proto::chat::services;
    use test_case::test_case;

    use super::*;
    use crate::api::backups::UnauthenticatedChatApi;
    use crate::api::testutil::fixed_seed_test_rng;
    use crate::grpc::testutil::{
        GrpcOverrideRequestValidator, RequestValidator, collect_up_to_and_including_first_error,
        err, ok, req, run_tests_with_generic_responses,
    };

    /// A variation of `==` that ignores header order, since the gRPC encoding of this type uses a
    /// protobuf map for the headers, which is not guaranteed to preserve order.
    ///
    /// Structured as a curried function (and takes a `Result`) for compatibility with [`test_case`]
    /// `using` syntax.
    fn assert_same<E: Debug>(expected: UploadForm) -> impl Fn(Result<UploadForm, E>) {
        let expected_headers = HashMap::from_iter(expected.headers);
        move |actual| {
            let UploadForm {
                cdn,
                key,
                headers,
                signed_upload_url,
            } = actual.expect("success");
            assert_eq!(expected.cdn, cdn);
            assert_eq!(expected.key, key);
            pretty_assertions::assert_eq!(expected_headers, HashMap::<_, _>::from_iter(headers));
            assert_eq!(expected.signed_upload_url, signed_upload_url);
        }
    }

    #[test_case(ok(GetUploadFormResponse {
        response: Some(get_upload_form_response::Response::UploadForm(common::UploadForm {
            cdn: 123,
            key: "abcde".to_owned(),
            headers: HashMap::from_iter([
                ("one".to_owned(), "val1".to_owned()),
                ("two".to_owned(), "val2".to_owned()),
            ]),
            signed_upload_location: "http://example.org/upload".to_owned()
        }))
    }) => using assert_same(UploadForm {
        cdn: 123,
        key: "abcde".into(),
        headers: vec![("one".into(), "val1".into()), ("two".into(), "val2".into())],
        signed_upload_url: "http://example.org/upload".into(),
    }))]
    #[test_case(ok(GetUploadFormResponse {
        response: Some(get_upload_form_response::Response::FailedAuthentication(FailedZkAuthentication {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(GetUploadFormFailure::Unauthorized)))]
    #[test_case(ok(GetUploadFormResponse {
        response: Some(get_upload_form_response::Response::ExceedsMaxUploadLength(FailedPrecondition {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(GetUploadFormFailure::UploadTooLarge)))]
    #[test_case(ok(GetUploadFormResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(err(tonic::Code::Internal) => matches Err(RequestError::Unexpected { .. }))]
    fn test_get_upload_form(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let validator = GrpcOverrideRequestValidator {
            message: services::BackupsAnonymous::GetUploadForm.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.backup.BackupsAnonymous/GetUploadForm",
                    GetUploadFormRequest {
                        signed_presentation: Some(SignedPresentation {
                            presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                            presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
                        }),
                        upload_type: Some(UploadType::Messages(MessagesUploadType {})),
                        upload_length: 12345,
                    },
                ),
                response,
            },
        };

        Unauth(&validator)
            .get_upload_form(
                &BackupAuth::generate_for_testing(
                    zkgroup::backups::BackupCredentialType::Media,
                    &mut fixed_seed_test_rng(),
                ),
                12345,
                &mut fixed_seed_test_rng(),
            )
            .now_or_never()
            .expect("sync")
    }

    #[test_case(ok(GetUploadFormResponse {
        response: Some(get_upload_form_response::Response::UploadForm(common::UploadForm {
            cdn: 123,
            key: "abcde".to_owned(),
            headers: HashMap::from_iter([
                ("one".to_owned(), "val1".to_owned()),
                ("two".to_owned(), "val2".to_owned()),
            ]),
            signed_upload_location: "http://example.org/upload".to_owned()
        }))
    }) => using assert_same(UploadForm {
        cdn: 123,
        key: "abcde".into(),
        headers: vec![("one".into(), "val1".into()), ("two".into(), "val2".into())],
        signed_upload_url: "http://example.org/upload".into(),
    }))]
    #[test_case(ok(GetUploadFormResponse {
        response: Some(get_upload_form_response::Response::FailedAuthentication(FailedZkAuthentication {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(GetUploadFormFailure::Unauthorized)))]
    #[test_case(ok(GetUploadFormResponse {
        response: Some(get_upload_form_response::Response::ExceedsMaxUploadLength(FailedPrecondition {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(GetUploadFormFailure::UploadTooLarge)))]
    #[test_case(ok(GetUploadFormResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(err(tonic::Code::Internal) => matches Err(RequestError::Unexpected { .. }))]
    fn test_get_media_upload_form(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let validator = GrpcOverrideRequestValidator {
            message: services::BackupsAnonymous::GetUploadForm.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.backup.BackupsAnonymous/GetUploadForm",
                    GetUploadFormRequest {
                        signed_presentation: Some(SignedPresentation {
                            presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                            presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
                        }),
                        upload_length: 12345,
                        upload_type: Some(UploadType::Media(MediaUploadType {})),
                    },
                ),
                response,
            },
        };

        Unauth(&validator)
            .get_media_upload_form(
                &BackupAuth::generate_for_testing(
                    zkgroup::backups::BackupCredentialType::Media,
                    &mut fixed_seed_test_rng(),
                ),
                12345,
                &mut fixed_seed_test_rng(),
            )
            .now_or_never()
            .expect("sync")
    }

    #[test_case(ok(SetPublicKeyResponse {
        response: Some(set_public_key_response::Response::Success(Default::default()))
    }) => matches Ok(()))]
    #[test_case(ok(SetPublicKeyResponse {
        response: Some(set_public_key_response::Response::FailedAuthentication(FailedZkAuthentication {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(BackupAuthCredentialRejected)))]
    #[test_case(ok(SetPublicKeyResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    fn test_set_public_key(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<(), RequestError<BackupAuthCredentialRejected>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.backup.BackupsAnonymous/SetPublicKey",
                SetPublicKeyRequest {
                    signed_presentation: Some(SignedPresentation {
                        presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                        presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
                    }),
                    public_key: BackupAuth::TEST_SIGNING_KEY_PUB.to_vec(),
                },
            ),
            response,
        };

        Unauth(&validator)
            .set_backup_public_key(
                &BackupAuth::generate_for_testing(
                    zkgroup::backups::BackupCredentialType::Media,
                    &mut fixed_seed_test_rng(),
                ),
                &mut fixed_seed_test_rng(),
            )
            .now_or_never()
            .expect("sync")
    }

    #[test_case(ok(GetCdnCredentialsResponse {
        response: Some(get_cdn_credentials_response::Response::CdnCredentials(get_cdn_credentials_response::CdnCredentials {
            headers: HashMap::from_iter([
                ("one".to_string(), "val1".to_string()),
                ("two".to_string(), "val2".to_string()),
            ]),
        }))
    }) => matches Ok(CdnCredentials { headers }) if <HashMap<String, String>>::from_iter(headers.clone()) == HashMap::from_iter([
        ("one".to_string(), "val1".to_string()),
        ("two".to_string(), "val2".to_string()),
    ]))]
    #[test_case(ok(GetCdnCredentialsResponse {
        response: Some(get_cdn_credentials_response::Response::FailedAuthentication(FailedZkAuthentication {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(BackupAuthCredentialRejected)))]
    #[test_case(ok(GetCdnCredentialsResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    fn test_get_cdn_credentials(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<CdnCredentials, RequestError<BackupAuthCredentialRejected>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.backup.BackupsAnonymous/GetCdnCredentials",
                GetCdnCredentialsRequest {
                    signed_presentation: Some(SignedPresentation {
                        presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                        presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
                    }),
                    cdn: 15,
                },
            ),
            response,
        };

        Unauth(&validator)
            .get_backup_cdn_credentials(
                &BackupAuth::generate_for_testing(
                    zkgroup::backups::BackupCredentialType::Media,
                    &mut fixed_seed_test_rng(),
                ),
                15,
                &mut fixed_seed_test_rng(),
            )
            .now_or_never()
            .expect("sync")
    }

    #[test_case(ok(GetSvrBCredentialsResponse {
        response: Some(get_svr_b_credentials_response::Response::SvrbCredentials(get_svr_b_credentials_response::SvrBCredentials {
            username: "user".to_string(),
            password: "pass".to_string(),
        }))
    }) => matches Ok((username, password)) if username == "user" && password == "pass")]
    #[test_case(ok(GetSvrBCredentialsResponse {
        response: Some(get_svr_b_credentials_response::Response::FailedAuthentication(FailedZkAuthentication {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(BackupAuthCredentialRejected)))]
    #[test_case(ok(GetSvrBCredentialsResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    fn test_get_svrb_credentials(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<(String, String), RequestError<BackupAuthCredentialRejected>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.backup.BackupsAnonymous/GetSvrBCredentials",
                GetSvrBCredentialsRequest {
                    signed_presentation: Some(SignedPresentation {
                        presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                        presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
                    }),
                },
            ),
            response,
        };

        Unauth(&validator)
            .get_backup_svrb_credentials(
                &BackupAuth::generate_for_testing(
                    zkgroup::backups::BackupCredentialType::Media,
                    &mut fixed_seed_test_rng(),
                ),
                &mut fixed_seed_test_rng(),
            )
            .now_or_never()
            .expect("sync")
            // Map to something that supports Debug, for test_case failure output.
            .map(|libsignal_net::auth::Auth { username, password }| (username, password))
    }

    #[test_case(ok(RefreshResponse {
        response: Some(refresh_response::Response::Success(Default::default()))
    }) => matches Ok(()))]
    #[test_case(ok(RefreshResponse {
        response: Some(refresh_response::Response::FailedAuthentication(FailedZkAuthentication {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(BackupAuthCredentialRejected)))]
    #[test_case(ok(RefreshResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    fn test_refresh(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<(), RequestError<BackupAuthCredentialRejected>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.backup.BackupsAnonymous/Refresh",
                RefreshRequest {
                    signed_presentation: Some(SignedPresentation {
                        presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                        presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
                    }),
                },
            ),
            response,
        };

        Unauth(&validator)
            .refresh_backup(
                &BackupAuth::generate_for_testing(
                    zkgroup::backups::BackupCredentialType::Media,
                    &mut fixed_seed_test_rng(),
                ),
                &mut fixed_seed_test_rng(),
            )
            .now_or_never()
            .expect("sync")
    }

    #[test_case(ok(DeleteAllResponse {
        response: Some(delete_all_response::Response::Success(Default::default()))
    }) => matches Ok(()))]
    #[test_case(ok(DeleteAllResponse {
        response: Some(delete_all_response::Response::FailedAuthentication(FailedZkAuthentication {
            description: "bad!".to_owned()
        }))
    }) => matches Err(RequestError::Other(BackupAuthCredentialRejected)))]
    #[test_case(ok(DeleteAllResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    fn test_delete_all(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<(), RequestError<BackupAuthCredentialRejected>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.backup.BackupsAnonymous/DeleteAll",
                RefreshRequest {
                    signed_presentation: Some(SignedPresentation {
                        presentation: BackupAuth::EXPECTED_TEST_PRESENTATION.to_vec(),
                        presentation_signature: BackupAuth::EXPECTED_TEST_SIGNATURE.to_vec(),
                    }),
                },
            ),
            response,
        };

        Unauth(&validator)
            .backup_delete_all(
                &BackupAuth::generate_for_testing(
                    zkgroup::backups::BackupCredentialType::Media,
                    &mut fixed_seed_test_rng(),
                ),
                &mut fixed_seed_test_rng(),
            )
            .now_or_never()
            .expect("sync")
    }

    #[test]
    fn test_copy_media() {
        use super::test_cases::*;
        run_tests_with_generic_responses(
            copy_media_test_cases(),
            |chat: Unauth<_>, items| async move {
                collect_up_to_and_including_first_error(chat.copy_backup_media(
                    &BackupAuth::generate_for_testing(
                        zkgroup::backups::BackupCredentialType::Media,
                        &mut fixed_seed_test_rng(),
                    ),
                    items,
                    &mut fixed_seed_test_rng(),
                ))
                .await
            },
            |resp, result| {
                assert_eq!(
                    resp.len(),
                    result.len(),
                    "result had different number of items than expected. expected: {resp:#?}, actual: {result:#?}"
                );
                for (i, (next, expected)) in result.iter().zip(resp).enumerate() {
                    match expected {
                        CopyBackupMediaOut::Item(expected_item) => {
                            let Ok(item) = next else {
                                panic!("{i}: should not have been stream-level error");
                            };
                            assert_eq!(&expected_item, item, "{i}");
                        }
                        CopyBackupMediaOut::InvalidDataInStream => {
                            assert_matches!(
                                next,
                                Err(RequestError::Unexpected { log_safe })
                                if log_safe == "malformed media id (1 bytes)",
                                "{i}"
                            );
                        }
                        CopyBackupMediaOut::CredentialRejected => {
                            assert_matches!(
                                next,
                                Err(RequestError::Other(BackupAuthCredentialRejected)),
                                "{i}"
                            );
                        }
                        CopyBackupMediaOut::CredentialRejectedWithoutAppropriateServerInfo => {
                            assert_matches!(
                                next,
                                Err(RequestError::Unexpected { log_safe })
                                if log_safe == "stream closed with no reason",
                                "{i}"
                            );
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn test_delete_media() {
        use super::test_cases::*;
        run_tests_with_generic_responses(
            delete_media_test_cases(),
            |chat: Unauth<_>, items| async move {
                collect_up_to_and_including_first_error(chat.delete_backup_media(
                    &BackupAuth::generate_for_testing(
                        zkgroup::backups::BackupCredentialType::Media,
                        &mut fixed_seed_test_rng(),
                    ),
                    &items,
                    &mut fixed_seed_test_rng(),
                ))
                .await
            },
            |resp, result| {
                assert_eq!(
                    resp.len(),
                    result.len(),
                    "result had different number of items than expected. expected: {resp:#?}, actual: {result:#?}"
                );
                for (i, (next, expected)) in result.iter().zip(resp).enumerate() {
                    match expected {
                        DeleteBackupMediaOut::Item(expected_item) => {
                            let Ok(item) = next else {
                                panic!("{i}: should not have been stream-level error");
                            };
                            assert_eq!(&expected_item, item, "{i}");
                        }
                        DeleteBackupMediaOut::InvalidDataInStream => {
                            assert_matches!(
                                next,
                                Err(RequestError::Unexpected { log_safe })
                                if log_safe == "malformed media id (1 bytes)",
                                "{i}"
                            );
                        }
                        DeleteBackupMediaOut::CredentialRejected => {
                            assert_matches!(
                                next,
                                Err(RequestError::Other(BackupAuthCredentialRejected)),
                                "{i}"
                            );
                        }
                        DeleteBackupMediaOut::CredentialRejectedWithoutAppropriateServerInfo => {
                            assert_matches!(
                                next,
                                Err(RequestError::Unexpected { log_safe })
                                if log_safe == "stream closed with no reason",
                                "{i}"
                            );
                        }
                    }
                }
            },
        );
    }
}
