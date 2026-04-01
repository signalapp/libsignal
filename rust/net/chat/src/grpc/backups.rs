//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_net_grpc::proto::chat::backup::backups_anonymous_client::BackupsAnonymousClient;
use libsignal_net_grpc::proto::chat::backup::get_upload_form_request::{
    MediaUploadType, MessagesUploadType, UploadType,
};
use libsignal_net_grpc::proto::chat::backup::{
    GetUploadFormRequest, GetUploadFormResponse, SignedPresentation, get_upload_form_response,
};
use libsignal_net_grpc::proto::chat::common;
use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, FailedZkAuthentication};

use super::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::api::backups::{BackupAuth, BackupAuthPresentation, GetUploadFormFailure};
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

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::fmt::Debug;

    use futures_util::FutureExt as _;
    use test_case::test_case;

    use super::*;
    use crate::api::backups::UnauthenticatedChatApi;
    use crate::api::testutil::fixed_seed_test_rng;
    use crate::grpc::testutil::{RequestValidator, err, ok, req};

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
        response: http::Response<Vec<u8>>,
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.backup.BackupsAnonymous/GetUploadForm",
                GetUploadFormRequest {
                    signed_presentation: Some(SignedPresentation {
                        presentation: BackupAuth::EXPECTED_PRESENTATION.to_vec(),
                        presentation_signature: BackupAuth::EXPECTED_SIGNATURE.to_vec(),
                    }),
                    upload_type: Some(UploadType::Messages(MessagesUploadType {})),
                    upload_length: 12345,
                },
            ),
            response,
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
        response: http::Response<Vec<u8>>,
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.backup.BackupsAnonymous/GetUploadForm",
                GetUploadFormRequest {
                    signed_presentation: Some(SignedPresentation {
                        presentation: BackupAuth::EXPECTED_PRESENTATION.to_vec(),
                        presentation_signature: BackupAuth::EXPECTED_SIGNATURE.to_vec(),
                    }),
                    upload_length: 12345,
                    upload_type: Some(UploadType::Media(MediaUploadType {})),
                },
            ),
            response,
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
}
