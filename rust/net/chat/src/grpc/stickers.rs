//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_net_grpc::proto::chat::attachments::attachments_client::AttachmentsClient;
use libsignal_net_grpc::proto::chat::attachments::{
    GetStickerUploadFormRequest, GetStickerUploadFormResponse as GetStickerUploadFormResponseProto,
};

use super::{GrpcServiceProvider, log_and_send};
use crate::api::{Auth, RequestError, S3UploadForm};
use crate::logging::Redact;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct GetStickerUploadFormsResponse {
    pub pack_id: String,
    pub manifest_upload_form: S3UploadForm,
    pub sticker_upload_forms: Vec<S3UploadForm>,
}

impl<T: GrpcServiceProvider> Auth<T> {
    pub async fn get_sticker_upload_forms(
        &self,
        number_of_stickers: u32,
    ) -> Result<GetStickerUploadFormsResponse, RequestError<Infallible>> {
        let mut client = AttachmentsClient::new(self.0.service());
        let request = GetStickerUploadFormRequest {
            sticker_count: number_of_stickers,
        };
        let desc = Redact(&request).to_string();
        let GetStickerUploadFormResponseProto {
            pack_id,
            manifest_upload_form,
            sticker_upload_forms,
        } = log_and_send("auth", &desc, || client.get_sticker_upload_form(request))
            .await?
            .into_inner();

        if sticker_upload_forms.len()
            != usize::try_from(number_of_stickers)
                .expect("maximum number of stickers fits in a usize")
        {
            return Err(RequestError::Unexpected {
                log_safe: format!(
                    "asked for {number_of_stickers} sticker upload forms, got {}",
                    sticker_upload_forms.len()
                ),
            });
        }

        Ok(GetStickerUploadFormsResponse {
            pack_id,
            manifest_upload_form: manifest_upload_form
                .ok_or_else(|| RequestError::Unexpected {
                    log_safe: "missing manifest_upload_form".to_owned(),
                })?
                .try_into()?,
            sticker_upload_forms: sticker_upload_forms
                .into_iter()
                .map(S3UploadForm::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl std::fmt::Display for Redact<GetStickerUploadFormRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let GetStickerUploadFormRequest { sticker_count } = self.0;
        f.debug_struct("GetStickerUploadFormRequest")
            // We could hide this, but it's going to be obvious from the rest of the logs.
            .field("sticker_count", &sticker_count)
            .finish()
    }
}

pub mod test_cases {
    use libsignal_net_grpc::proto::chat::common::S3UploadForm as S3UploadFormProto;

    use super::*;
    use crate::grpc::GrpcTestCase;

    #[expect(clippy::large_enum_variant)]
    pub enum GetStickerUploadFormsOut {
        Success(GetStickerUploadFormsResponse),
        Invalid,
    }

    pub fn get_sticker_upload_form_test_cases() -> Vec<
        GrpcTestCase<
            u32,
            GetStickerUploadFormRequest,
            GetStickerUploadFormResponseProto,
            GetStickerUploadFormsOut,
        >,
    > {
        let method = "/org.signal.chat.attachments.Attachments/GetStickerUploadForm";
        let upload_form_proto = S3UploadFormProto {
            key: "k-manifest".to_owned(),
            credential: "mellon".to_owned(),
            acl: "644".to_owned(),
            algorithm: "Sha5000".to_owned(),
            date: "20260902T000000Z".to_owned(),
            policy: "base64==".to_owned(),
            signature: "a0b1c2d3e4f50617".to_owned(),
        };
        let upload_form_response = S3UploadForm {
            key: "k-manifest".to_owned(),
            credential: "mellon".to_owned(),
            acl: "644".to_owned(),
            algorithm: "Sha5000".to_owned(),
            date: "20260902T000000Z".to_owned(),
            policy: "base64==".to_owned(),
            signature: "a0b1c2d3e4f50617".to_owned(),
        };

        vec![
            GrpcTestCase {
                name: "success".to_owned(),
                method: method.to_owned(),
                request: 3,
                request_grpc: GetStickerUploadFormRequest { sticker_count: 3 },
                response_grpc: GetStickerUploadFormResponseProto {
                    pack_id: "abcd".to_owned(),
                    manifest_upload_form: Some(upload_form_proto.clone()),
                    sticker_upload_forms: vec![
                        S3UploadFormProto {
                            key: "k-0".to_owned(),
                            ..upload_form_proto.clone()
                        },
                        S3UploadFormProto {
                            key: "k-1".to_owned(),
                            ..upload_form_proto.clone()
                        },
                        S3UploadFormProto {
                            key: "k-2".to_owned(),
                            ..upload_form_proto.clone()
                        },
                    ],
                },
                response: GetStickerUploadFormsOut::Success(GetStickerUploadFormsResponse {
                    pack_id: "abcd".to_owned(),
                    manifest_upload_form: upload_form_response.clone(),
                    sticker_upload_forms: vec![
                        S3UploadForm {
                            key: "k-0".to_owned(),
                            ..upload_form_response.clone()
                        },
                        S3UploadForm {
                            key: "k-1".to_owned(),
                            ..upload_form_response.clone()
                        },
                        S3UploadForm {
                            key: "k-2".to_owned(),
                            ..upload_form_response.clone()
                        },
                    ],
                }),
            },
            GrpcTestCase {
                name: "wrong number of forms".to_string(),
                method: method.to_string(),
                request: 3,
                request_grpc: GetStickerUploadFormRequest { sticker_count: 3 },
                response_grpc: GetStickerUploadFormResponseProto {
                    pack_id: "abcd".to_owned(),
                    manifest_upload_form: Some(upload_form_proto.clone()),
                    sticker_upload_forms: vec![
                        S3UploadFormProto {
                            key: "k-0".to_owned(),
                            ..upload_form_proto.clone()
                        },
                        S3UploadFormProto {
                            key: "k-1".to_owned(),
                            ..upload_form_proto.clone()
                        },
                    ],
                },
                response: GetStickerUploadFormsOut::Invalid,
            },
            GrpcTestCase {
                name: "missing manifest form".to_string(),
                method: method.to_string(),
                request: 3,
                request_grpc: GetStickerUploadFormRequest { sticker_count: 3 },
                response_grpc: GetStickerUploadFormResponseProto {
                    pack_id: "abcd".to_owned(),
                    manifest_upload_form: None,
                    sticker_upload_forms: vec![
                        S3UploadFormProto {
                            key: "k-0".to_owned(),
                            ..upload_form_proto.clone()
                        },
                        S3UploadFormProto {
                            key: "k-1".to_owned(),
                            ..upload_form_proto.clone()
                        },
                        S3UploadFormProto {
                            key: "k-2".to_owned(),
                            ..upload_form_proto.clone()
                        },
                    ],
                },
                response: GetStickerUploadFormsOut::Invalid,
            },
        ]
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;
    use crate::grpc::testutil::run_tests;

    #[test]
    fn test_get_sticker_upload_forms() {
        use test_cases::*;
        run_tests(
            get_sticker_upload_form_test_cases(),
            |chat: Auth<_>, number_of_stickers| async move {
                chat.get_sticker_upload_forms(number_of_stickers).await
            },
            |resp, result| match resp {
                GetStickerUploadFormsOut::Success(expected) => {
                    assert_eq!(expected, result.expect("success"))
                }
                GetStickerUploadFormsOut::Invalid => {
                    assert_matches!(result, Err(RequestError::Unexpected { .. }))
                }
            },
        );
    }
}
