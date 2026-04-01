//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::str::FromStr;

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use libsignal_net::chat::Request;
use libsignal_net_grpc::proto::chat::services;

use super::{
    CustomError, GetUploadFormResponse, OverWs, TryIntoResponse, WsConnection, expect_empty_body,
};
use crate::api::backups::{BackupAuth, BackupAuthPresentation, GetUploadFormFailure};
use crate::api::{RequestError, Unauth, UploadForm};

impl BackupAuthPresentation {
    const AUTH_HEADER_NAME: http::HeaderName = http::HeaderName::from_static("x-signal-zk-auth");
    const SIGNATURE_HEADER_NAME: http::HeaderName =
        http::HeaderName::from_static("x-signal-zk-auth-signature");

    fn to_headers(&self) -> impl IntoIterator<Item = (http::HeaderName, http::HeaderValue)> {
        [
            (
                Self::AUTH_HEADER_NAME,
                BASE64_STANDARD
                    .encode(&self.serialized_presentation)
                    .try_into()
                    .expect("base64 is a valid header value"),
            ),
            (
                Self::SIGNATURE_HEADER_NAME,
                BASE64_STANDARD
                    .encode(&self.signature)
                    .try_into()
                    .expect("base64 is a valid header value"),
            ),
        ]
    }
}

#[async_trait]
impl<T: WsConnection> crate::api::backups::UnauthenticatedChatApi<OverWs> for Unauth<T> {
    async fn get_upload_form(
        &self,
        auth: &BackupAuth,
        upload_size: u64,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let auth = auth.present(rng)?;

        let response = self
            .send(
                "unauth",
                "/v1/archives/upload/form",
                Request {
                    method: http::Method::GET,
                    path: format!("/v1/archives/upload/form?uploadLength={upload_size}")
                        .parse()
                        .expect("valid"),
                    headers: http::HeaderMap::from_iter(auth.to_headers()),
                    body: None,
                },
            )
            .await?;

        let GetUploadFormResponse(upload_form) = response.try_into_response().map_err(|e| {
            e.into_request_error(Self::ALLOW_RATE_LIMIT_CHALLENGES, |response| {
                let high_level_error = match response.status.as_u16() {
                    401 | 403 => GetUploadFormFailure::Unauthorized,
                    413 => GetUploadFormFailure::UploadTooLarge,
                    _ => return CustomError::NoCustomHandling,
                };
                expect_empty_body(response, "/v1/archives/upload/form");
                high_level_error.into()
            })
        })?;

        Ok(upload_form)
    }

    async fn get_media_upload_form(
        &self,
        auth: &BackupAuth,
        upload_size: u64,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        // Note that we're using the same setting name as get_upload_form.
        // This is a single endpoint in gRPC, and having two settings for them wouldn't add much.
        if let Some(grpc) =
            self.grpc_service_to_use_instead(services::BackupsAnonymous::GetUploadForm.into())
        {
            return Unauth(grpc)
                .get_media_upload_form(auth, upload_size, rng)
                .await;
        }

        let auth = auth.present(rng)?;
        let path = format!("/v1/archives/media/upload/form?uploadLength={upload_size}");
        let response = self
            .send(
                "unauth",
                &path,
                Request {
                    method: http::Method::GET,
                    path: http::uri::PathAndQuery::from_str(&path).expect("Path should parse"),
                    headers: http::HeaderMap::from_iter(auth.to_headers()),
                    body: None,
                },
            )
            .await?;

        let GetUploadFormResponse(upload_form) = response.try_into_response().map_err(|e| {
            e.into_request_error(Self::ALLOW_RATE_LIMIT_CHALLENGES, |response| {
                let high_level_error = match response.status.as_u16() {
                    401 | 403 => GetUploadFormFailure::Unauthorized,
                    413 => GetUploadFormFailure::UploadTooLarge,
                    _ => return CustomError::NoCustomHandling,
                };
                expect_empty_body(response, "/v1/archives/media/upload/form");
                high_level_error.into()
            })
        })?;

        Ok(upload_form)
    }
}

#[cfg(test)]
mod test {
    use futures_util::FutureExt as _;
    use libsignal_net::chat;
    use test_case::test_case;

    use super::*;
    use crate::api::backups::UnauthenticatedChatApi;
    use crate::api::testutil::fixed_seed_test_rng;
    use crate::ws::testutil::{RequestValidator, empty, json};

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
    #[test_case(empty(401) => matches Err(RequestError::Other(GetUploadFormFailure::Unauthorized)))]
    #[test_case(empty(403) => matches Err(RequestError::Other(GetUploadFormFailure::Unauthorized)))]
    #[test_case(empty(413) => matches Err(RequestError::Other(GetUploadFormFailure::UploadTooLarge)))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    fn test_get_upload_form(
        response: chat::Response,
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static(
                    "/v1/archives/upload/form?uploadLength=12345",
                ),
                headers: http::HeaderMap::from_iter([
                    (
                        BackupAuthPresentation::AUTH_HEADER_NAME,
                        http::HeaderValue::try_from(
                            BASE64_STANDARD.encode(BackupAuth::EXPECTED_PRESENTATION),
                        )
                        .expect("valid"),
                    ),
                    (
                        BackupAuthPresentation::SIGNATURE_HEADER_NAME,
                        http::HeaderValue::try_from(
                            BASE64_STANDARD.encode(BackupAuth::EXPECTED_SIGNATURE),
                        )
                        .expect("valid"),
                    ),
                ]),
                body: None,
            },
            response,
        };

        Unauth(validator)
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
    #[test_case(empty(401) => matches Err(RequestError::Other(GetUploadFormFailure::Unauthorized)))]
    #[test_case(empty(403) => matches Err(RequestError::Other(GetUploadFormFailure::Unauthorized)))]
    #[test_case(empty(413) => matches Err(RequestError::Other(GetUploadFormFailure::UploadTooLarge)))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    fn test_get_media_upload_form(
        response: chat::Response,
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>> {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static(
                    "/v1/archives/media/upload/form?uploadLength=12345",
                ),
                headers: http::HeaderMap::from_iter([
                    (
                        BackupAuthPresentation::AUTH_HEADER_NAME,
                        http::HeaderValue::try_from(
                            BASE64_STANDARD.encode(BackupAuth::EXPECTED_PRESENTATION),
                        )
                        .expect("valid"),
                    ),
                    (
                        BackupAuthPresentation::SIGNATURE_HEADER_NAME,
                        http::HeaderValue::try_from(
                            BASE64_STANDARD.encode(BackupAuth::EXPECTED_SIGNATURE),
                        )
                        .expect("valid"),
                    ),
                ]),
                body: None,
            },
            response,
        };

        Unauth(validator)
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
