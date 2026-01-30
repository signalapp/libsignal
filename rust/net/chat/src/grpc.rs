//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `grpc` module and its submodules implement a chat server based on the gRPC messages from
//! [libsignal-net-grpc](libsignal_net_grpc).

mod profiles;
mod usernames;

use std::future::Future;

use itertools::Itertools;
use libsignal_net::infra::errors::RetryLater;
use libsignal_net_grpc::proto::google;
use prost::Message as _;
use tonic::codegen::StdError;

use crate::api::{DisconnectedError, RequestError};
use crate::logging::DebugAsStrOrBytes;

/// Marker type for use in [`crate::api`] traits.
pub enum OverGrpc {}

/// A single place to put all the constraints we rely on to use [`tonic::client::GrpcService`] with
/// [`async_trait`] in this crate.
///
/// May some day be replaceable by a trait alias, <https://github.com/rust-lang/rust/issues/41517>.
pub trait GrpcService:
    tonic::client::GrpcService<
        tonic::body::Body,
        ResponseBody = <Self as GrpcService>::ResponseBody,
        Error: Into<StdError>,
        Future: Send,
    > + Send
{
    /// Redeclared form of [`GrpcService::ResponseBody`](tonic::client::GrpcService::ResponseBody).
    ///
    /// This is redeclared because otherwise rustc isn't consistent about propagating the `'static`
    /// requirement to use sites.
    type ResponseBody: http_body::Body<Data = bytes::Bytes, Error: Into<StdError> + Send>
        + Send
        + 'static;
}
impl<T> GrpcService for T
where
    T: tonic::client::GrpcService<tonic::body::Body, Error: Into<StdError>, Future: Send> + Send,
    T::ResponseBody:
        http_body::Body<Data = bytes::Bytes, Error: Into<StdError> + Send> + Send + 'static,
{
    type ResponseBody = T::ResponseBody;
}

/// A wrapper around [`GrpcService`] providing the sharing behavior expected by the traits in
/// [`crate::api`].
///
/// `tonic` expects a gRPC service instance to be owned by the particular client we use to send
/// messages for the duration of that message. However, the chat-server API we present to clients
/// allows multiple messages to be sent from different threads without synchronization, and we run
/// multiple gRPC services over the same connection (Keys, Messages, etc).
pub trait GrpcServiceProvider: Send + Sync {
    type Service: GrpcService;
    fn service(&self) -> Self::Service;
}

/// Any clonable [`GrpcService`] can provide itself as a service.
impl<T: GrpcService + Clone + Sync> GrpcServiceProvider for T {
    type Service = Self;
    fn service(&self) -> Self {
        self.clone()
    }
}

async fn log_and_send<F, R>(
    log_tag: &'static str,
    log_safe_description: &str,
    operation: impl FnOnce() -> F,
) -> tonic::Result<R>
where
    F: Future<Output = tonic::Result<R>>,
{
    let request_id = rand::random::<u16>();
    log::info!("[{log_tag} {request_id:04x}] {log_safe_description}");

    let result = operation().await;
    match &result {
        Ok(_) => log::info!("[{log_tag} {request_id:04x}] {log_safe_description} OK"),
        Err(status) => {
            // Use the Debug implementation to print the status code's name, which is easier to
            // identify than the human-readable description.
            // (But first, *guess* that there's no user data stored in tonic::Code by checking that
            // it's still Copy. The full check for this is the exhaustive match in
            // into_default_request_error.)
            static_assertions::assert_impl_all!(tonic::Code: Copy);
            log::warn!(
                "[{log_tag} {request_id:04x}] {log_safe_description} {:?}",
                status.code()
            );
            log::debug!(
                "[{log_tag} {request_id:04x}] {:?} {} ({:?}): {:?}",
                status.code(),
                status.message(),
                status.metadata(),
                DebugAsStrOrBytes(status.details())
            );
        }
    }
    result
}

impl<E> From<tonic::Status> for RequestError<E> {
    fn from(status: tonic::Status) -> Self {
        if let Some((details, info)) = extract_server_side_error(&status) {
            return request_error_from_server_side_error_info(details, info);
        }

        match status.code() {
            // TODO: Unfortunately we can't distinguish between server-side gRPC library errors and
            // client-side gRPC library errors, so we need to pick a conservative interpretation of all
            // of these codes.
            tonic::Code::DeadlineExceeded => return RequestError::Timeout,
            tonic::Code::Unavailable => {
                return RequestError::Disconnected(DisconnectedError::Closed);
            }

            tonic::Code::ResourceExhausted => {
                if let Some(retry_after_seconds) = status
                    .metadata()
                    .get(http::header::RETRY_AFTER.as_str())
                    .and_then(|header| header.to_str().ok())
                    .and_then(|retry_after_str| retry_after_str.parse().ok())
                {
                    return libsignal_net::infra::errors::RetryLater {
                        retry_after_seconds,
                    }
                    .into();
                }
                // TODO: also handle challenges here?
            }
            tonic::Code::Ok => {
                return RequestError::Unexpected {
                    log_safe: "request failed with status OK".to_owned(),
                };
            }

            tonic::Code::Cancelled
            | tonic::Code::Unknown
            | tonic::Code::InvalidArgument
            | tonic::Code::NotFound
            | tonic::Code::AlreadyExists
            | tonic::Code::PermissionDenied
            | tonic::Code::FailedPrecondition
            | tonic::Code::Aborted
            | tonic::Code::OutOfRange
            | tonic::Code::Unimplemented
            | tonic::Code::Internal
            | tonic::Code::DataLoss
            | tonic::Code::Unauthenticated => {}
        }
        // Use the Debug implementation to get the name of the code, which is easier to identify than
        // the human-readable description.
        RequestError::Unexpected {
            log_safe: format!("unexpected error: {:?}", status.code()),
        }
    }
}

const GRPC_STATUS_DETAILS_METADATA_KEY: &str = "grpc-status-details-bin";
const SIGNAL_ERRORINFO_DOMAIN: &str = "grpc.chat.signal.org";

/// Extracts info from an error response if and only if it's from the chat server.
fn extract_server_side_error(
    status: &tonic::Status,
) -> Option<(google::rpc::Status, google::rpc::ErrorInfo)> {
    let details = status
        .metadata()
        .get_bin(GRPC_STATUS_DETAILS_METADATA_KEY)?
        .to_bytes()
        .inspect_err(|_e| log::warn!("invalid encoding for {GRPC_STATUS_DETAILS_METADATA_KEY}"))
        .ok()?;
    let grpc_status = google::rpc::Status::decode(details)
        .inspect_err(|_e| log::warn!("invalid encoding of google::rpc::Status message"))
        .ok()?;
    if grpc_status.code != i32::from(status.code()) {
        log::warn!(
            "gRPC response had status {:?} ({}), but details had code {}",
            status.code(),
            i32::from(status.code()),
            grpc_status.code
        );
    }

    let all_detail_info = matching_details::<google::rpc::ErrorInfo>(&grpc_status.details);
    let mut info = None;
    for next_info in all_detail_info {
        if next_info.domain == SIGNAL_ERRORINFO_DOMAIN {
            if info.is_none() {
                info = Some(next_info);
            } else {
                log::warn!(
                    "multiple '{SIGNAL_ERRORINFO_DOMAIN}' errors; ignoring later {}",
                    next_info.reason
                );
            }
        } else {
            log::warn!(
                "ignoring non-Signal error info with domain {}",
                next_info.domain,
            );
        }
    }
    let info = info?;
    Some((grpc_status, info))
}

/// Given error info known to be from the chat server, produce a proper high-level error to return
/// to the app.
fn request_error_from_server_side_error_info<E>(
    grpc_status: google::rpc::Status,
    info: google::rpc::ErrorInfo,
) -> RequestError<E> {
    debug_assert_eq!(info.domain, SIGNAL_ERRORINFO_DOMAIN);

    match info.reason.as_str() {
        // TODO: These two need to be reported globally as well as for this specific request.
        "UPGRADE_REQUIRED" => RequestError::Disconnected(DisconnectedError::ConnectionInvalidated),
        "INVALID_CREDENTIALS" => {
            RequestError::Disconnected(DisconnectedError::ConnectionInvalidated)
        }
        // This is always a client bug, such as a linked device trying to do an action that can only
        // be done from the primary.
        "BAD_AUTHENTICATION" => RequestError::Unexpected {
            log_safe: "BAD_AUTHENTICATION".to_owned(),
        },
        "CONSTRAINT_VIOLATED" => {
            let bad_fields = matching_details::<google::rpc::BadRequest>(&grpc_status.details)
                .at_most_one()
                .unwrap_or_else(|mut e| {
                    log::warn!(
                        "multiple google::rpc::BadRequest entries in error details; using first"
                    );
                    e.next()
                })
                .map(|req| req.field_violations)
                .unwrap_or_default();
            for violation in &bad_fields {
                // This is a debug-level log because it might contain user data.
                log::debug!(
                    "{}: {} ({})",
                    violation.field,
                    violation.description,
                    violation.reason
                );
            }
            if bad_fields.is_empty() {
                RequestError::Unexpected {
                    log_safe: "CONSTRAINT_VIOLATED".to_owned(),
                }
            } else {
                // We don't include the specific mistake because it might include user data.
                RequestError::Unexpected {
                    log_safe: format!(
                        "CONSTRAINT_VIOLATED for fields {}",
                        bad_fields
                            .iter()
                            .map(|violation| &violation.field)
                            .join(", ")
                    ),
                }
            }
        }
        "RESOURCE_EXHAUSTED" | "UNAVAILABLE" => {
            // UNAVAILABLE is unlikely to have RetryInfo, but it doesn't really hurt to check.
            if let Some(mut retry_delay) =
                matching_details::<google::rpc::RetryInfo>(&grpc_status.details)
                    .at_most_one()
                    .unwrap_or_else(|mut e| {
                        log::warn!(
                            "multiple google::rpc::RetryInfo entries in error details; using first"
                        );
                        e.next()
                    })
                    .and_then(|info| info.retry_delay)
            {
                retry_delay.normalize();
                // Round up so that we're guaranteed to wait *at least* this long.
                let retry_after_seconds =
                    retry_delay.seconds + i64::from(retry_delay.nanos.clamp(0, 1));
                return RequestError::RetryLater(RetryLater {
                    retry_after_seconds: u32::try_from(
                        retry_after_seconds.clamp(0, u32::MAX.into()),
                    )
                    .expect("clamped"),
                });
            }
            RequestError::ServerSideError
        }
        reason => RequestError::Unexpected {
            log_safe: format!("unexpected error in domain '{SIGNAL_ERRORINFO_DOMAIN}': {reason}"),
        },
    }
}

fn matching_details<M: Default + prost::Name>(
    details: &[prost_types::Any],
) -> impl Iterator<Item = M> {
    let expected_url = M::type_url();
    details
        .iter()
        .filter(move |p| p.type_url == expected_url)
        .filter_map(|p| {
            M::decode(&p.value[..])
                .inspect_err(|_e| log::warn!("invalid encoding of {} message", M::full_name()))
                .ok()
        })
}

#[cfg(test)]
pub(crate) mod testutil {
    use futures_util::FutureExt as _;
    use http_body_util::BodyExt as _;
    use tonic::Status;

    use super::*;

    pub(crate) fn req(uri: &str, body: impl prost::Message + 'static) -> http::Request<Vec<u8>> {
        let body = tonic::codec::EncodeBody::new_client(
            tonic_prost::ProstEncoder::new(Default::default()),
            futures_util::stream::iter([Ok(body)]),
            None,
            None,
        )
        .collect()
        .now_or_never()
        .expect("non-blocking encoding")
        .expect("can read entire message")
        .to_bytes()
        .into();

        http::Request::builder()
            .method(http::Method::POST)
            .header(
                http::header::CONTENT_TYPE,
                tonic::metadata::GRPC_CONTENT_TYPE,
            )
            .header(http::header::TE, "trailers")
            .uri(uri)
            .body(body)
            .expect("can build request")
    }

    pub(crate) fn ok(response: impl prost::Message + 'static) -> http::Response<Vec<u8>> {
        let body = tonic::codec::EncodeBody::new_server(
            tonic_prost::ProstEncoder::new(Default::default()),
            futures_util::stream::iter([Ok(response)]),
            None,
            Default::default(),
            None,
        )
        .collect()
        .now_or_never()
        .expect("non-blocking encoding")
        .expect("can read entire message")
        .to_bytes()
        .into();
        http::Response::new(body)
    }

    pub(crate) fn err(code: tonic::Code) -> http::Response<Vec<u8>> {
        Status::new(code, "").into_http()
    }

    pub(crate) struct RequestValidator {
        pub expected: http::Request<Vec<u8>>,
        pub response: http::Response<Vec<u8>>,
    }

    impl tower_service::Service<http::Request<tonic::body::Body>> for &'_ RequestValidator {
        type Response = http::Response<http_body_util::Full<bytes::Bytes>>;

        type Error = hyper::Error;

        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
            let (parts, body) = req.into_parts();
            let body = body
                .collect()
                .now_or_never()
                .expect("non-blocking requests for testing")
                .expect("can read entire body")
                .to_bytes();
            pretty_assertions::assert_eq!(self.expected.uri(), &parts.uri, "uri");
            pretty_assertions::assert_eq!(self.expected.method(), &parts.method, "method");
            pretty_assertions::assert_eq!(self.expected.headers(), &parts.headers, "headers");
            pretty_assertions::assert_eq!(&self.expected.body()[..], &body, "body");

            std::future::ready(Ok(self.response.clone().map(|body| body.into())))
        }
    }

    static_assertions::assert_impl_all!(&'_ RequestValidator: GrpcService);
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;
    use tonic::metadata::MetadataValue;

    use super::*;

    #[test]
    fn test_extract_server_side_error() {
        let original_error_info = google::rpc::ErrorInfo {
            reason: "CONSTRAINT_VIOLATED".into(),
            domain: SIGNAL_ERRORINFO_DOMAIN.into(),
            metadata: Default::default(),
        };
        let unrelated_error_info = google::rpc::ErrorInfo {
            reason: "something else".into(),
            domain: "nonexistent.signal.org".into(),
            metadata: Default::default(),
        };
        let original_status = google::rpc::Status {
            code: tonic::Code::InvalidArgument.into(),
            message: "bad arg (inner)".into(),
            details: vec![
                prost_types::Any {
                    type_url: "test.signal.org/RandomTestingTypeToIgnore".into(),
                    value: vec![],
                },
                prost_types::Any::from_msg(&unrelated_error_info).expect("can encode"),
                prost_types::Any::from_msg(&original_error_info).expect("can encode"),
            ],
        };

        let mut response = tonic::Status::invalid_argument("bad arg (outer)");
        response.metadata_mut().insert_bin(
            GRPC_STATUS_DETAILS_METADATA_KEY,
            MetadataValue::from_bytes(&original_status.encode_to_vec()),
        );
        let (status, error_info) = extract_server_side_error(&response).expect("can extract");
        assert_eq!(status, original_status);
        assert_eq!(error_info, original_error_info);
    }

    #[test]
    fn test_extract_server_side_error_without_details() {
        let mut response = tonic::Status::invalid_argument("bad arg (outer)");
        assert_matches!(extract_server_side_error(&response), None);

        let mut status = google::rpc::Status {
            code: tonic::Code::InvalidArgument.into(),
            message: "bad arg (inner)".into(),
            details: vec![],
        };
        response.metadata_mut().insert_bin(
            GRPC_STATUS_DETAILS_METADATA_KEY,
            MetadataValue::from_bytes(&status.encode_to_vec()),
        );
        assert_matches!(extract_server_side_error(&response), None);

        let unrelated_error_info = google::rpc::ErrorInfo {
            reason: "something else".into(),
            domain: "nonexistent.signal.org".into(),
            metadata: Default::default(),
        };
        status.details = vec![
            prost_types::Any {
                type_url: "test.signal.org/RandomTestingTypeToIgnore".into(),
                value: vec![],
            },
            prost_types::Any::from_msg(&unrelated_error_info).expect("can encode"),
        ];
        response.metadata_mut().insert_bin(
            GRPC_STATUS_DETAILS_METADATA_KEY,
            MetadataValue::from_bytes(&status.encode_to_vec()),
        );
        assert_matches!(extract_server_side_error(&response), None);
    }

    fn test_error_conversion(
        reason: &str,
        details: Vec<impl prost::Name>,
    ) -> RequestError<std::convert::Infallible> {
        let status = google::rpc::Status {
            code: tonic::Code::Unknown.into(),
            message: "example failure".into(),
            details: details
                .into_iter()
                .map(|item| prost_types::Any::from_msg(&item).expect("can encode"))
                .chain([prost_types::Any {
                    type_url: "test.signal.org/RandomTestingTypeToIgnore".into(),
                    value: vec![],
                }])
                .collect(),
        };
        let info = google::rpc::ErrorInfo {
            reason: reason.into(),
            domain: SIGNAL_ERRORINFO_DOMAIN.into(),
            metadata: Default::default(),
        };
        request_error_from_server_side_error_info(status, info)
    }

    #[test_case("GARBAGE" => matches RequestError::Unexpected { .. })]
    #[test_case("UPGRADE_REQUIRED" => matches RequestError::Disconnected(DisconnectedError::ConnectionInvalidated))]
    #[test_case("INVALID_CREDENTIALS" => matches RequestError::Disconnected(DisconnectedError::ConnectionInvalidated))]
    #[test_case("BAD_AUTHENTICATION" => matches RequestError::Unexpected { .. })]
    #[test_case("CONSTRAINT_VIOLATED" => matches RequestError::Unexpected { .. })]
    #[test_case("RESOURCE_EXHAUSTED" => matches RequestError::ServerSideError)]
    #[test_case("UNAVAILABLE" => matches RequestError::ServerSideError)]
    fn test_simple_error_conversion(reason: &str) -> RequestError<std::convert::Infallible> {
        test_error_conversion(reason, Vec::<prost_types::Any>::new())
    }

    #[test_case("RESOURCE_EXHAUSTED")]
    #[test_case("UNAVAILABLE")]
    fn test_retry_later(reason: &str) {
        let info = vec![
            google::rpc::RetryInfo {
                retry_delay: Some(prost_types::Duration {
                    seconds: 10,
                    nanos: 2,
                }),
            },
            google::rpc::RetryInfo {
                retry_delay: Some(prost_types::Duration {
                    seconds: 20,
                    nanos: 5,
                }),
            },
        ];
        assert_matches!(
            test_error_conversion(reason, info),
            RequestError::RetryLater(RetryLater {
                retry_after_seconds: 11
            })
        );

        let garbage_info = vec![google::rpc::RetryInfo { retry_delay: None }];
        assert_matches!(
            test_error_conversion(reason, garbage_info),
            RequestError::ServerSideError
        );
    }

    #[test]
    fn test_constraint_violated() {
        let reason = "CONSTRAINT_VIOLATED";
        let info = vec![
            google::rpc::BadRequest {
                field_violations: vec![
                    google::rpc::bad_request::FieldViolation {
                        field: "fooField".into(),
                        description: "POISON".into(),
                        reason: "POISON".into(),
                        localized_message: Some(google::rpc::LocalizedMessage {
                            locale: "en-US".into(),
                            message: "POISON".into(),
                        }),
                    },
                    google::rpc::bad_request::FieldViolation {
                        field: "barField".into(),
                        description: "POISON".into(),
                        reason: "POISON".into(),
                        localized_message: None,
                    },
                ],
            },
            google::rpc::BadRequest {
                field_violations: vec![google::rpc::bad_request::FieldViolation {
                    field: "POISON".into(),
                    description: "POISON".into(),
                    reason: "POISON".into(),
                    localized_message: None,
                }],
            },
        ];

        let description = assert_matches!(
            test_error_conversion(reason, info),
            RequestError::Unexpected { log_safe } => log_safe
        );
        assert!(description.contains("fooField"));
        assert!(description.contains("barField"));
        assert!(!description.contains("POISON"));
    }
}
