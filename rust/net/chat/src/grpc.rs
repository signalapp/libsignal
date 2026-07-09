//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `grpc` module and its submodules implement a chat server based on the gRPC messages from
//! [libsignal-net-grpc](libsignal_net_grpc).

pub mod backups;
pub mod devices;
mod messages;
mod profiles;
pub mod usernames;

use std::convert::Infallible;
use std::error::Error;
use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;

use futures_util::{Stream, StreamExt as _, TryFutureExt as _, TryStream, TryStreamExt as _};
use itertools::Itertools;
use libsignal_core::LogSafeDisplay;
use libsignal_net::infra::errors::RetryLater;
use libsignal_net::infra::http_client::{Http2TransportError, Http2TransportErrorKind};
use libsignal_net_grpc::proto::chat::messages::ChallengeRequired as ChallengeRequiredProto;
use libsignal_net_grpc::proto::google;
use prost::Message as _;
use tonic::codegen::StdError;

use crate::api::{ChallengeOption, DisconnectedError, RateLimitChallenge, RequestError};
use crate::logging::{DebugAsStrOrBytes, Redact, RedactHex};

/// Marker type for use in [`crate::api`] traits.
pub enum OverGrpc {}

/// The item type for a streaming gRPC response.
pub type StreamResult<T, E = Infallible> = Result<T, RequestError<E>>;

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

/// A tonic encoder and decoder that passes byte buffers through unchanged, letting tonic
/// add the gRPC framing and nothing else.
struct PassthroughCodec;

impl tonic::codec::Codec for PassthroughCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = Self;
    type Decoder = Self;

    fn encoder(&mut self) -> Self::Encoder {
        PassthroughCodec
    }
    fn decoder(&mut self) -> Self::Decoder {
        PassthroughCodec
    }
}

impl tonic::codec::Encoder for PassthroughCodec {
    type Item = Vec<u8>;
    type Error = tonic::Status;
    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        use bytes::BufMut;
        dst.put(&item[..]);
        Ok(())
    }
}

impl tonic::codec::Decoder for PassthroughCodec {
    type Item = Vec<u8>;
    type Error = tonic::Status;
    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        use bytes::Buf;
        Ok(Some(src.copy_to_bytes(src.remaining()).into()))
    }
}

pub fn raw_grpc(
    log_tag: &'static str,
    service_provider: impl GrpcServiceProvider,
    service_name: &str,
    method: &str,
    payload: Vec<u8>,
) -> impl Future<Output = Result<Vec<u8>, RequestError<Infallible>>> {
    let mut client = tonic::client::Grpc::new(service_provider.service());
    let path = http::uri::PathAndQuery::from_maybe_shared(format!("/{service_name}/{method}"))
        .expect("valid URI path");
    log_and_send(log_tag, method, || async move {
        let response = client
            .unary(tonic::Request::new(payload), path, PassthroughCodec)
            .await?;
        Ok(response.into_inner())
    })
}

/// Performs a single operation, assumed to be a gRPC request, with logging at the start and end.
async fn log_and_send<F, R, E>(
    log_tag: &'static str,
    log_safe_description: &str,
    operation: impl FnOnce() -> F,
) -> Result<R, RequestError<E>>
where
    F: Future<Output = tonic::Result<R>>,
{
    let request_id = rand::random::<u16>();
    log::info!("[{log_tag} {request_id:04x}] {log_safe_description}");

    match operation().await {
        Ok(x) => {
            log::info!("[{log_tag} {request_id:04x}] {log_safe_description} done");
            Ok(x)
        }
        Err(status) => {
            // Assume that this endpoint does not produce any request-specific gRPC-level errors.
            // (These are usually only used for streams.)
            // Note that we still have to convert to RequestError<Infallible> at first, because E
            // may not be LogSafeDisplay.
            let err =
                convert_error_and_log(status, log_tag, log_safe_description, request_id, |_, _| {
                    None
                });
            Err(err.with_other())
        }
    }
}

/// Debug-logs a `tonic::Status`, then converts it using [`RequestError::from_tonic_status`] and
/// logs the result at warning level before returning.
///
/// Used by both [`log_and_send`] and [`send_request_with_streaming_response`].
fn convert_error_and_log<E>(
    status: tonic::Status,
    log_tag: &str,
    log_safe_request_description: &str,
    request_id: u16,
    handle_server_side_error: impl FnOnce(
        &google::rpc::Status,
        &google::rpc::ErrorInfo,
    ) -> Option<RequestError<E>>,
) -> RequestError<E>
where
    E: LogSafeDisplay,
{
    // Use the Debug implementation to print the status code's name, which is easier to identify
    // than the human-readable description.
    // (But first, *guess* that there's no user data stored in tonic::Code by checking that it's
    // still Copy. The full check for this is the exhaustive match in from_tonic_status.)
    static_assertions::assert_impl_all!(tonic::Code: Copy);
    let code = status.code();
    log::debug!(
        "[{log_tag} {request_id:04x}] {:?} {} ({:?}): {:?}",
        status.code(),
        status.message(),
        status.metadata(),
        DebugAsStrOrBytes(status.details())
    );
    let err = RequestError::from_tonic_status(status, handle_server_side_error);
    log::warn!(
        "[{log_tag} {request_id:04x}] {log_safe_request_description} {:?}: {}",
        code,
        err.log_safe_display()
    );
    err
}

/// Helper to transform `tonic` streaming responses into `libsignal-net-chat` high-level streams.
///
/// While these API docs will attempt to walk you through the whole thing, it will really make more
/// sense if you look at a use site. Here's an example call:
///
/// ```ignored
/// send_request_with_streaming_response(
///     "unauth",
///     self.grpc_service(),
///     || Ok(SomeRequest { id: validate_id(id_param)? }),
///     |service, request| async move {
///         SpecificClient::new(service).do_something(request).await
///     },
///     |response| response.service_id.try_into().map_err(|_| RequestError::Unexpected {
///         log_safe: "malformed service ID".to_owned(),
///     }),
///     |status| process(matching_details::<CustomInfo>(&status.details)),
/// )
/// ```
///
/// The result type is a `Stream<Result<T, RequestError<E>>>`, to be treated as a [`TryStream`]; any
/// top-level error signals the stream is no longer worth reading from.
///
/// The `make_request` parameter is called immediately, so it can use borrowed captures. If it
/// produces an error, the resulting stream will contain only that error and be ready immediately.
/// The request type it returns must be `Display`able with [`Redact`].
///
/// The `send_request` parameter is also called immediately after the request is successfully
/// created. It should send the request (without calling [`log_and_send`]). Note that even though
/// tonic request APIs return Futures themselves, wrapping with an extra `async move {}` is the
/// easiest way to deal with the lifetime of the service. Similarly, even though the service could
/// have been passed in already wrapped as the first argument, doing so seems to be beyond the
/// compiler's ability to infer a type for the `service` parameter.
///
/// The `handle_response` parameter is called on each item of the response. Remember that any errors
/// produced here will end the stream; if the stream has items that can individually represent
/// failures, they should be nested within the `Ok(T)` case.
///
/// Finally, `handle_stream_abort` is called if the server terminates the stream with a
/// `STREAM_CLOSED` error in the Signal error domain. In this case the appropriate information
/// should be extracted using [`matching_details`] and turned into a high-level error.
/// (`send_request_with_streaming_response` will take care of logging it for you.) The use of
/// `Result` in the return type allows for early exits.
fn send_request_with_streaming_response<
    Serv,
    Req: DisplayableRequest,
    RespStream: TryStream<Error = tonic::Status>,
    F: Future<Output = tonic::Result<tonic::Response<RespStream>>> + 'static,
    T,
    E: LogSafeDisplay + 'static,
>(
    log_tag: &'static str,
    service: Serv,
    make_request: impl FnOnce() -> StreamResult<Req, E>,
    send_request: impl FnOnce(Serv, Req) -> F,
    mut handle_response: impl FnMut(RespStream::Ok) -> StreamResult<T, E> + 'static,
    mut handle_stream_abort: impl FnMut(&google::rpc::Status) -> StreamResult<Infallible, E> + 'static,
) -> impl Stream<Item = StreamResult<T, E>> + 'static {
    // Run `make_request` and `send_request` synchronously so we don't need to capture them.
    let initial_state = make_request().map(|request| {
        let log_safe_description = Arc::new(request.log_safe_description());

        let request_id = rand::random::<u16>();
        log::info!("[{log_tag} {request_id:04x}] {log_safe_description}");

        let log_safe_description_for_errors = log_safe_description.clone();
        let handle_tonic_error = move |status| {
            convert_error_and_log(
                status,
                log_tag,
                &log_safe_description_for_errors,
                request_id,
                |status, info| match info.reason.as_str() {
                    "STREAM_CLOSED" => {
                        let Err(e) = handle_stream_abort(status);
                        Some(e)
                    }
                    _ => None,
                },
            )
        };

        let fut = send_request(service, request);
        (log_safe_description, request_id, handle_tonic_error, fut)
    });

    async move {
        let (log_safe_description, request_id, mut handle_tonic_error, fut) = initial_state?;

        let response = fut.await.map_err(&mut handle_tonic_error)?;

        log::debug!("[{log_tag} {request_id:04x}] {log_safe_description} start of stream");

        let stream = response
            .into_inner()
            .map_err(handle_tonic_error)
            .and_then(move |next| std::future::ready(handle_response(next)))
            .chain(futures_util::stream::poll_fn(move |_cx| {
                log::info!("[{log_tag} {request_id:04x}] {log_safe_description} done");
                std::task::Poll::Ready(None)
            }));
        Ok(stream)
    }
    .try_flatten_stream()
}

/// Helper trait for [`send_request_with_streaming_response`].
///
/// If the blanket impl requirement is written directly on `send_request_with_streaming_response`,
/// type inference of the request fails.
trait DisplayableRequest {
    /// Equivalent to `Redact(self).to_string()`.
    fn log_safe_description(&self) -> String;
}
impl<T> DisplayableRequest for T
where
    Redact<T>: Display,
{
    fn log_safe_description(&self) -> String {
        Redact(self).to_string()
    }
}

impl<E> RequestError<E> {
    /// Converts a tonic `Status` to a `RequestError`, whether it's a proper server-side error, a
    /// transport error, or a library-level error.
    ///
    /// The `handle_server_side_error` can provide request-specific handling for errors tagged with
    /// the Signal error domain; returning `None` falls through to request-agnostic handling for
    /// these errors. If there are no request-specific errors for a given request, return `None`
    /// unconditionally.
    fn from_tonic_status(
        status: tonic::Status,
        handle_server_side_error: impl FnOnce(
            &google::rpc::Status,
            &google::rpc::ErrorInfo,
        ) -> Option<Self>,
    ) -> Self {
        if let Some(transport_error) = status
            .source()
            .and_then(|source| source.downcast_ref::<Http2TransportError>())
        {
            log::debug!("HTTP/2 transport error: {transport_error:?}");
            log::info!(
                "HTTP/2 transport error: {}",
                transport_error.kind().log_safe_display()
            );
            // If hyper gives an error, we need to disconnect. Any higher-level issues would be
            // handled at the HTTP/2 level. A hyper error means that there's something wrong with
            // the HTTP/2 level.
            return RequestError::Disconnected(match transport_error.kind() {
                Http2TransportErrorKind::Closed => DisconnectedError::Closed,
                e @ (Http2TransportErrorKind::Unknown
                | Http2TransportErrorKind::BodyWriteAborted
                | Http2TransportErrorKind::Canceled
                | Http2TransportErrorKind::IncompleteMessage
                | Http2TransportErrorKind::Shutdown
                | Http2TransportErrorKind::Timeout
                | Http2TransportErrorKind::ParseStatus
                | Http2TransportErrorKind::Parse
                | Http2TransportErrorKind::User) => DisconnectedError::Transport {
                    log_safe: format!("HTTP/2 transport error: {}", e.log_safe_display()),
                },
            });
        }

        if let Some((details, info)) = extract_server_side_error(&status) {
            return handle_server_side_error(&details, &info)
                .unwrap_or_else(|| request_error_from_server_side_error_info(&details, &info));
        }

        // At this point, the error must be in the gRPC layer. Unfortunately we can't distinguish
        // between server-side gRPC library errors and client-side gRPC library errors, and neither
        // do we trust that they're log-safe, so we need to pick a conservative interpretation of
        // all of these codes. That being said, any hyper transport errors have been handled above.
        log::debug!(
            "request failed with status {:?}: {}",
            status.code(),
            status.message(),
        );
        match status.code() {
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
                // Fall through to the "unexpected" case.
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

const SIGNAL_ERRORINFO_DOMAIN: &str = "grpc.chat.signal.org";

/// Extracts info from an error response if and only if it's from the chat server.
fn extract_server_side_error(
    status: &tonic::Status,
) -> Option<(google::rpc::Status, google::rpc::ErrorInfo)> {
    let details = status.details();
    if details.is_empty() {
        return None;
    }
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
    grpc_status: &google::rpc::Status,
    info: &google::rpc::ErrorInfo,
) -> RequestError<E> {
    debug_assert_eq!(info.domain, SIGNAL_ERRORINFO_DOMAIN);
    log::debug!("identified as Signal-originated error...");

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
            let bad_fields =
                single_matching_details::<google::rpc::BadRequest>(&grpc_status.details)
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
            if let Some(retry_delay) =
                single_matching_details::<google::rpc::RetryInfo>(&grpc_status.details)
                    .and_then(|info| info.retry_delay)
            {
                // TODO: Use i32::div_ceil when that's stabilized.
                // https://github.com/rust-lang/rust/issues/88581
                fn nanos_to_secs_ceil(dividend: i32) -> i32 {
                    const DIVISOR: i32 = 1_000_000_000;
                    // Normal Div rounds towards 0.
                    let result = dividend / DIVISOR;
                    if dividend > 0 && dividend % DIVISOR != 0 {
                        result + 1
                    } else {
                        result
                    }
                }

                // Round up so that we're guaranteed to wait *at least* this long.
                let retry_after_seconds = retry_delay
                    .seconds
                    .saturating_add(nanos_to_secs_ceil(retry_delay.nanos).into());
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
    log::debug!("looking for {expected_url} in error details...");
    details
        .iter()
        .filter(move |p| p.type_url == expected_url)
        .filter_map(|p| {
            M::decode(&p.value[..])
                .inspect_err(|_e| log::warn!("invalid encoding of {} message", M::full_name()))
                .ok()
        })
}

fn single_matching_details<M: Default + prost::Name>(details: &[prost_types::Any]) -> Option<M> {
    matching_details(details)
        .at_most_one()
        .unwrap_or_else(|mut e| {
            log::warn!(
                "multiple {} entries in error details; using first",
                M::full_name()
            );
            e.next()
        })
}

impl TryFrom<ChallengeRequiredProto> for RateLimitChallenge {
    type Error = RequestError<std::convert::Infallible>;

    fn try_from(value: ChallengeRequiredProto) -> Result<Self, Self::Error> {
        use libsignal_net_grpc::proto::chat::messages::challenge_required;

        let ChallengeRequiredProto {
            token,
            challenge_options,
            retry_after_seconds,
        } = value;

        Ok(RateLimitChallenge {
            token,
            options: challenge_options
                .into_iter()
                .map(|raw_option| {
                    match challenge_required::ChallengeType::try_from(raw_option)
                        .unwrap_or_default()
                    {
                        challenge_required::ChallengeType::Unspecified => {
                            Err(RequestError::Unexpected {
                                log_safe: format!(
                                    "unspecified or unknown challenge option ({raw_option})"
                                ),
                            })
                        }
                        challenge_required::ChallengeType::Captcha => Ok(ChallengeOption::Captcha),
                        challenge_required::ChallengeType::PushChallenge => {
                            Ok(ChallengeOption::PushChallenge)
                        }
                    }
                })
                .try_collect()?,
            retry_later: retry_after_seconds.map(|seconds| RetryLater {
                retry_after_seconds: seconds.try_into().unwrap_or(u32::MAX),
            }),
        })
    }
}

impl std::fmt::Display for Redact<libsignal_net_grpc::proto::chat::common::ServiceIdentifier> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.try_as_service_id() {
            Some(id) => write!(f, "{}", Redact(id)),
            None => f
                .debug_struct("ServiceIdentifier")
                .field("id", &self.0.identity_type)
                .field("uuid", &RedactHex(&hex::encode(&self.0.uuid)))
                .finish(),
        }
    }
}

pub struct GrpcTestCase<Request, RequestGrpc, ResponseGrpc, Response> {
    pub name: String,
    pub method: String,
    pub request: Request,
    pub request_grpc: RequestGrpc,
    pub response_grpc: ResponseGrpc,
    pub response: Response,
}

// Utilities used by exported test cases (and thus not `cfg(test)`).
pub mod test_case_util {
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;
    use futures_util::FutureExt as _;
    use http_body_util::BodyExt as _;
    use libsignal_net::chat::fake::BodyWithTrailers;

    use super::*;

    pub const GRPC_STATUS_HEADER: http::HeaderName = http::HeaderName::from_static("grpc-status");
    pub(crate) const GRPC_STATUS_DETAILS_HEADER: http::HeaderName =
        http::HeaderName::from_static("grpc-status-details-bin");

    pub(crate) fn stream(
        response: Vec<impl prost::Message + 'static>,
        error: Option<tonic::Status>,
    ) -> http::Response<BodyWithTrailers> {
        let encoded = tonic::codec::EncodeBody::new_server(
            tonic_prost::ProstEncoder::new(Default::default()),
            futures_util::stream::iter(response.into_iter().map(Ok).chain(error.map(Err))),
            None,
            Default::default(),
            None,
        )
        .collect()
        .now_or_never()
        .expect("non-blocking encoding")
        .expect("can read entire message");

        let trailers = encoded.trailers().cloned().unwrap_or_default();
        let body = encoded.to_bytes().into();

        http::Response::new(BodyWithTrailers {
            data: body,
            trailers,
        })
    }

    pub(crate) fn status_for_server_side_error(
        code: tonic::Code,
        reason: &str,
        extra_info: Vec<impl prost::Name>,
    ) -> tonic::Status {
        let original_error_info = google::rpc::ErrorInfo {
            reason: reason.into(),
            domain: SIGNAL_ERRORINFO_DOMAIN.into(),
            metadata: Default::default(),
        };
        let original_status = google::rpc::Status {
            code: code.into(),
            message: "message".to_owned(),
            details: extra_info
                .into_iter()
                .map(|info| prost_types::Any::from_msg(&info).expect("can encode"))
                .chain([prost_types::Any::from_msg(&original_error_info).expect("can encode")])
                .collect(),
        };

        tonic::Status::from_header_map(&http::HeaderMap::from_iter([
            (
                GRPC_STATUS_HEADER,
                http::HeaderValue::from_str(&original_status.code.to_string()).expect("valid"),
            ),
            (
                GRPC_STATUS_DETAILS_HEADER,
                http::HeaderValue::from_str(
                    &BASE64_STANDARD.encode(original_status.encode_to_vec()),
                )
                .expect("valid"),
            ),
        ]))
        .expect("valid")
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use futures_util::FutureExt as _;
    use http_body_util::BodyExt as _;
    use http_body_util::combinators::BoxBody;
    use libsignal_net::chat::fake::{BodyWithTrailers, IntoHttpBody};
    use tonic::Status;

    use super::test_case_util::*;
    use super::*;

    pub(crate) fn run_tests<
        Request,
        RequestGrpc: prost::Message + 'static,
        ResponseGrpc: prost::Message + 'static,
        Response,
        F: Future,
        Wrapper: From<RequestValidator<BodyWithTrailers>>,
    >(
        tests: impl IntoIterator<Item = GrpcTestCase<Request, RequestGrpc, ResponseGrpc, Response>>,
        invoke: impl Fn(Wrapper, Request) -> F,
        check: impl Fn(Response, F::Output),
    ) {
        run_tests_with_generic_responses(
            tests.into_iter().map(|item| GrpcTestCase {
                name: item.name,
                method: item.method,
                request: item.request,
                request_grpc: item.request_grpc,
                response_grpc: ok(item.response_grpc),
                response: item.response,
            }),
            invoke,
            check,
        )
    }

    pub(crate) fn run_tests_with_generic_responses<
        Request,
        RequestGrpc: prost::Message + 'static,
        ResponseHttp: IntoHttpBody,
        Response,
        F: Future,
        Wrapper: From<RequestValidator<ResponseHttp>>,
    >(
        tests: impl IntoIterator<
            Item = GrpcTestCase<Request, RequestGrpc, http::Response<ResponseHttp>, Response>,
        >,
        invoke: impl Fn(Wrapper, Request) -> F,
        check: impl Fn(Response, F::Output),
    ) {
        for test in tests {
            eprintln!("== {}", test.name);
            check(
                test.response,
                invoke(
                    RequestValidator {
                        expected: req(&test.method, test.request_grpc),
                        response: test.response_grpc,
                    }
                    .into(),
                    test.request,
                )
                .now_or_never()
                .expect("sync"),
            );
        }
    }

    pub(crate) fn encode_for_grpc<C: tonic::codec::Encoder<Error = Status>>(
        encoder: C,
        item: C::Item,
    ) -> Vec<u8> {
        // The difference between client and server only seems to matter when using compression.
        tonic::codec::EncodeBody::new_client(
            encoder,
            futures_util::stream::iter([Ok(item)]),
            None,
            None,
        )
        .collect()
        .now_or_never()
        .expect("non-blocking encoding")
        .expect("can read entire message")
        .to_bytes()
        .into()
    }

    pub(crate) fn req(uri: &str, body: impl prost::Message + 'static) -> http::Request<Vec<u8>> {
        let body = encode_for_grpc(tonic_prost::ProstEncoder::new(Default::default()), body);
        req_typed(uri, body)
    }

    pub(crate) fn req_typed<T>(uri: &str, body: T) -> http::Request<T> {
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

    pub(crate) fn ok(response: impl prost::Message + 'static) -> http::Response<BodyWithTrailers> {
        stream(vec![response], None)
    }

    pub(crate) fn err(code: tonic::Code) -> http::Response<BodyWithTrailers> {
        Status::new(code, "").into_http()
    }

    /// Validates that the [`WsConnection`] implementation of an API defers to the gRPC
    /// implementation when the `message` override is provided.
    ///
    /// Then defers to the inner validator for further checking and producing a response.
    pub(crate) struct GrpcOverrideRequestValidator<V> {
        pub(crate) validator: V,
        pub(crate) message: &'static str,
    }

    impl<V> crate::ws::WsConnection for GrpcOverrideRequestValidator<V>
    where
        V: Send + Sync,
        for<'a> &'a V: GrpcServiceProvider,
    {
        async fn send(
            &self,
            _log_tag: &'static str,
            _log_safe_path: &str,
            _request: libsignal_net::chat::Request,
        ) -> Result<libsignal_net::chat::Response, libsignal_net::chat::SendError> {
            panic!("We should be only sending grpc here");
        }

        fn grpc_service_to_use_instead(
            &self,
            message: &'static str,
        ) -> Option<impl GrpcServiceProvider> {
            assert_eq!(message, self.message);
            Some(&self.validator)
        }

        fn self_aci(&self) -> Option<libsignal_core::Aci> {
            Some(crate::api::testutil::TEST_SELF_ACI)
        }
    }

    /// Validates that a gRPC request matches in all parts of the underlying HTTP request, checking
    /// the body byte-for-byte.
    ///
    /// Prefer a [`GrpcOverrideRequestValidator`] containing a `RequestValidator` if the request has
    /// a corresponding config to switch between WS and gRPC implementations. Replace the
    /// `RequestValidator` with `TypedRequestValidator` if comparing the bodies using protobuf
    /// semantics (rather than bytewise) is important---it usually isn't.
    #[derive(Clone)]
    pub(crate) struct RequestValidator<T> {
        pub expected: http::Request<Vec<u8>>,
        pub response: http::Response<T>,
    }

    impl<T: IntoHttpBody + Clone> tower_service::Service<http::Request<tonic::body::Body>>
        for RequestValidator<T>
    {
        type Response =
            <&'static Self as tower_service::Service<http::Request<tonic::body::Body>>>::Response;
        type Error =
            <&'static Self as tower_service::Service<http::Request<tonic::body::Body>>>::Error;
        type Future =
            <&'static Self as tower_service::Service<http::Request<tonic::body::Body>>>::Future;

        fn poll_ready(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            let mut x: &Self = self;
            <&Self as tower_service::Service<http::Request<tonic::body::Body>>>::poll_ready(
                &mut x, cx,
            )
        }

        fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
            let mut x: &Self = self;
            <&Self as tower_service::Service<http::Request<tonic::body::Body>>>::call(&mut x, req)
        }
    }

    impl<T: IntoHttpBody + Clone> tower_service::Service<http::Request<tonic::body::Body>>
        for &'_ RequestValidator<T>
    {
        type Response = http::Response<BoxBody<bytes::Bytes, Infallible>>;

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

            if self.expected.body()[..] != body {
                let expected_body = DynMessage::decode_single_grpc_body(
                    bytes::Bytes::copy_from_slice(self.expected.body()),
                );
                let actual_body = DynMessage::decode_single_grpc_body(body);
                panic!("expected body: {expected_body:#?}\n\nactual body: {actual_body:#?}");
            }

            std::future::ready(Ok(self.response.clone().map(|body| body.into_http_body())))
        }
    }

    static_assertions::assert_impl_all!(&'_ RequestValidator<Vec<u8>>: GrpcService);

    static_assertions::assert_impl_all!(&'_ RequestValidator<BodyWithTrailers>: GrpcService);

    /// Like `RequestValidator`, but compares the decoded protobuf of the incoming request instead
    /// of the serialized bytes.
    ///
    /// Prefer `RequestValidator` if the protobuf does not contain any `map` fields, because it also
    /// checks that there are no extraneous fields in the body. (While protobuf permits fields to
    /// appear in any order, our prost implementation is consistent within a build, if not
    /// necessarily across versions. `map` is only a problem because it uses Rust's HashMap.)
    pub(crate) struct TypedRequestValidator<T> {
        pub expected: http::Request<T>,
        pub response: http::Response<BodyWithTrailers>,
    }

    impl<T> tower_service::Service<http::Request<tonic::body::Body>> for &'_ TypedRequestValidator<T>
    where
        T: MessageExt + PartialEq + std::fmt::Debug,
    {
        type Response = http::Response<BoxBody<bytes::Bytes, Infallible>>;

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

            let actual_body = T::decode_single_grpc_body(body).unwrap_or_else(|e| {
                panic!("body is not a valid {}: {}", std::any::type_name::<T>(), e)
            });
            pretty_assertions::assert_eq!(self.expected.body(), &actual_body, "body");

            std::future::ready(Ok(self.response.clone().map(|body| body.into_http_body())))
        }
    }

    /// Use to check that no gRPC calls happen at all (e.g. for a `should_panic` test, but don't
    /// forget to check the panic message in that case!).
    pub(crate) struct UnreachableValidator;

    impl tower_service::Service<http::Request<tonic::body::Body>> for &'_ UnreachableValidator {
        type Response = http::Response<http_body_util::Full<bytes::Bytes>>;

        type Error = hyper::Error;

        type Future = std::future::Pending<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            unreachable!("should not attempt to send");
        }

        fn call(&mut self, _req: http::Request<tonic::body::Body>) -> Self::Future {
            unreachable!("should not attempt to send");
        }
    }

    /// A protoscope-like helper type for decoding arbitrary protobuf messages.
    ///
    /// Always succeeds as long as the input is not malformed. Only intended for debugging.
    #[derive(Default)]
    pub(crate) struct DynMessage {
        fields: Vec<(u32, DynField)>,
    }

    /// See [`DynMessage`].
    enum DynField {
        Varint(usize),
        U32(u32),
        U64(u64),
        Bytes(bytes::Bytes),
        Nested(DynMessage),
    }

    trait MessageExt: Sized {
        fn decode_single_grpc_body(
            body: impl bytes::Buf + Send + 'static,
        ) -> Result<Self, tonic::Status>;
    }

    impl<T: prost::Message + Default + 'static> MessageExt for T {
        /// Given a gRPC HTTP body, decode a single request message from it.
        fn decode_single_grpc_body(
            body: impl bytes::Buf + Send + 'static,
        ) -> Result<Self, tonic::Status> {
            let decoder = tonic_prost::ProstDecoder::<Self>::default();
            let mut streaming = tonic::codec::Streaming::new_request(
                decoder,
                http_body_util::Full::new(body),
                None,
                None,
            );
            streaming
                .message()
                .now_or_never()
                .expect("ready")?
                .ok_or_else(|| tonic::Status::data_loss("missing body"))
        }
    }

    impl prost::Message for DynMessage {
        // This requirement is hidden in prost::Message and thus should be considered unstable,
        // which is why we only use this for debugging. The implementation is based on reading the
        // source for prost-derive.
        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: prost::encoding::wire_type::WireType,
            mut buf: &mut impl bytes::Buf,
            _ctx: prost::encoding::DecodeContext,
        ) -> Result<(), prost::DecodeError>
        where
            Self: Sized,
        {
            use prost::encoding::wire_type::WireType;
            let value = match wire_type {
                WireType::Varint => DynField::Varint(prost::decode_length_delimiter(buf)?),
                WireType::ThirtyTwoBit => DynField::U32(buf.try_get_u32_le().map_err(|_| {
                    #[expect(deprecated)]
                    prost::DecodeError::new("eof")
                })?),
                WireType::SixtyFourBit => DynField::U64(buf.try_get_u64_le().map_err(|_| {
                    #[expect(deprecated)]
                    prost::DecodeError::new("eof")
                })?),
                WireType::LengthDelimited => {
                    let len = prost::decode_length_delimiter(&mut buf)?;
                    if len > buf.remaining() {
                        return Err(
                            #[expect(deprecated)]
                            prost::DecodeError::new("eof"),
                        );
                    }
                    let bytes = buf.copy_to_bytes(len);
                    if let Ok(inner) = DynMessage::decode(bytes.clone()) {
                        DynField::Nested(inner)
                    } else {
                        DynField::Bytes(bytes)
                    }
                }
                WireType::StartGroup | WireType::EndGroup => {
                    return Err(
                        #[expect(deprecated)]
                        prost::DecodeError::new("groups unsupported"),
                    );
                }
            };
            self.fields.push((tag, value));
            Ok(())
        }

        fn clear(&mut self) {
            self.fields.clear();
        }

        fn encode_raw(&self, _buf: &mut impl bytes::BufMut)
        where
            Self: Sized,
        {
            unimplemented!("for decoding to debug only")
        }

        fn encoded_len(&self) -> usize {
            unimplemented!("for decoding to debug only")
        }
    }

    impl std::fmt::Debug for DynMessage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut out = f.debug_struct("DynMessage");
            for (tag, value) in &self.fields {
                out.field(&tag.to_string(), &value);
            }
            out.finish()
        }
    }

    impl std::fmt::Debug for DynField {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Use protoscope-like syntax.
            match self {
                Self::Varint(arg) => write!(f, "{arg}"),
                Self::U32(arg) => write!(f, "{arg}u32"),
                Self::U64(arg) => write!(f, "{arg}u64"),
                Self::Bytes(arg) => {
                    if arg.is_ascii() {
                        write!(f, "\"{}\"", arg.escape_ascii())
                    } else {
                        write!(f, "`{}`", hex::encode(arg))
                    }
                }
                Self::Nested(arg) => arg.fmt(f),
            }
        }
    }

    pub(crate) fn collect_up_to_and_including_first_error<S, T, E>(
        stream: S,
    ) -> impl Future<Output = Vec<S::Item>>
    where
        S: Stream<Item = Result<T, E>>,
    {
        // We want to emulate the behavior of "take up to the first error", but then also check the
        // error. Neither a simple `take_while` nor `try_collect` quite captures this, so we need a
        // little extra state.
        let mut stream_is_ok = true;
        stream
            .take_while(move |next| {
                std::future::ready(std::mem::replace(&mut stream_is_ok, next.is_ok()))
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use assert_matches::assert_matches;
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;
    use futures_util::FutureExt as _;
    use hyper::rt::ReadBufCursor;
    use libsignal_net::infra::http_client::Http2Client;
    use libsignal_net::infra::testutil::TestError;
    use test_case::test_case;

    use super::*;
    use crate::grpc::test_case_util::{
        GRPC_STATUS_DETAILS_HEADER, GRPC_STATUS_HEADER, status_for_server_side_error,
    };
    use crate::grpc::testutil::collect_up_to_and_including_first_error;

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

        let response = tonic::Status::from_header_map(&http::HeaderMap::from_iter([
            (
                GRPC_STATUS_HEADER,
                http::HeaderValue::from_static(const_str::to_str!(
                    tonic::Code::InvalidArgument as i32
                )),
            ),
            (
                GRPC_STATUS_DETAILS_HEADER,
                http::HeaderValue::from_str(
                    &BASE64_STANDARD.encode(original_status.encode_to_vec()),
                )
                .expect("valid"),
            ),
        ]))
        .expect("valid");
        let (status, error_info) = extract_server_side_error(&response).expect("can extract");
        assert_eq!(status, original_status);
        assert_eq!(error_info, original_error_info);
    }

    #[test]
    fn test_extract_server_side_error_without_details() {
        fn make_response(status: Option<&google::rpc::Status>) -> tonic::Status {
            tonic::Status::from_header_map(
                &status
                    .map(|status| {
                        (
                            GRPC_STATUS_DETAILS_HEADER,
                            http::HeaderValue::from_str(
                                &BASE64_STANDARD.encode(status.encode_to_vec()),
                            )
                            .expect("valid"),
                        )
                    })
                    .into_iter()
                    .chain([(
                        GRPC_STATUS_HEADER,
                        http::HeaderValue::from_static(const_str::to_str!(
                            tonic::Code::InvalidArgument as i32
                        )),
                    )])
                    .collect(),
            )
            .expect("valid")
        }

        let response = make_response(None);
        assert_matches!(extract_server_side_error(&response), None);

        let mut status = google::rpc::Status {
            code: tonic::Code::InvalidArgument.into(),
            message: "bad arg (inner)".into(),
            details: vec![],
        };
        let response = make_response(Some(&status));
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
        let response = make_response(Some(&status));
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
        request_error_from_server_side_error_info(&status, &info)
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
                retry_delay: Some(libsignal_net_grpc::Duration {
                    seconds: 10,
                    nanos: 2,
                }),
            },
            google::rpc::RetryInfo {
                retry_delay: Some(libsignal_net_grpc::Duration {
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

    #[test]
    fn test_transport_errors() {
        static_assertions::assert_type_eq_all!(
            Http2TransportError,
            <Http2Client<tonic::body::Body> as tower_service::Service<
                http::Request<tonic::body::Body>,
            >>::Error,
        );
        let hyper_err = {
            // We want to return a hyper error, but one does not simply construct a hyper::Error
            // There's no public API to do so! Instead, we come up with a situation that always
            // fails.
            struct Io;
            impl hyper::rt::Read for Io {
                fn poll_read(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    _buf: ReadBufCursor<'_>,
                ) -> Poll<Result<(), std::io::Error>> {
                    Poll::Ready(Err(std::io::Error::other("error")))
                }
            }
            impl hyper::rt::Write for Io {
                fn poll_write(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    _buf: &[u8],
                ) -> Poll<Result<usize, std::io::Error>> {
                    Poll::Ready(Err(std::io::Error::other("error")))
                }

                fn poll_flush(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<Result<(), std::io::Error>> {
                    Poll::Ready(Err(std::io::Error::other("error")))
                }

                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                ) -> Poll<Result<(), std::io::Error>> {
                    Poll::Ready(Err(std::io::Error::other("error")))
                }
            }
            match hyper::client::conn::http1::handshake::<_, String>(Io)
                .now_or_never()
                .expect("Future should return immediately")
            {
                Err(e) => e,
                Ok((_sender, conn)) => conn
                    .now_or_never()
                    .expect("future should return immediately")
                    .expect_err("the connection shouldn't succeed"),
            }
        };
        assert_matches!(
            RequestError::<Infallible>::from_tonic_status(
                tonic::Status::from_error(Box::new(Http2TransportError::Hyper(hyper_err))),
                |_, _| None
            ),
            RequestError::Disconnected(DisconnectedError::Transport { log_safe: _ })
        );
    }

    #[test_case(ChallengeRequiredProto {
        token: "".into(),
        challenge_options: vec![],
        retry_after_seconds: None,
    } => matches Ok(RateLimitChallenge { token, options, retry_later: None }) if token.is_empty() && options.is_empty())]
    #[test_case(ChallengeRequiredProto {
        token: "abc".into(),
        challenge_options: vec![],
        retry_after_seconds: None,
    } => matches Ok(RateLimitChallenge { token, options, retry_later: None }) if token == "abc" && options.is_empty())]
    #[test_case(ChallengeRequiredProto {
        token: "abc".into(),
        challenge_options: vec![],
        retry_after_seconds: Some(3),
    } => matches Ok(RateLimitChallenge { token, options, retry_later: Some(RetryLater { retry_after_seconds: 3 }) }) if token == "abc" && options.is_empty())]
    #[test_case(ChallengeRequiredProto {
        token: "abc".into(),
        challenge_options: vec![2, 1],
        retry_after_seconds: None,
    } => matches Ok(RateLimitChallenge { token, options, retry_later: None }) if token == "abc" && options == [ChallengeOption::PushChallenge, ChallengeOption::Captcha])]
    #[test_case(ChallengeRequiredProto {
        token: "abc".into(),
        challenge_options: vec![2, 1, 0],
        retry_after_seconds: None,
    } => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ChallengeRequiredProto {
        token: "abc".into(),
        challenge_options: vec![1, 50, 2],
        retry_after_seconds: None,
    } => matches Err(RequestError::Unexpected { .. }))]
    fn test_challenge_required(
        input: ChallengeRequiredProto,
    ) -> Result<RateLimitChallenge, RequestError<Infallible>> {
        RateLimitChallenge::try_from(input)
    }

    struct U32Request(u32);
    impl Display for Redact<U32Request> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("U32Request").field(&self.0.0).finish()
        }
    }

    #[test]
    fn test_stream() {
        let stream = send_request_with_streaming_response(
            "test",
            0u32,
            || Ok(U32Request(5)),
            |start: u32, U32Request(finish)| {
                let contents =
                    futures_util::stream::iter(start..finish).map(|i| Ok(i.to_le_bytes()));
                std::future::ready(Ok(tonic::Response::from(contents)))
            },
            |next| -> StreamResult<_> { Ok(u32::from_le_bytes(next)) },
            |_| unreachable!(),
        );
        let contents: Vec<_> = stream.collect().now_or_never().expect("ready");
        assert_matches!(&contents[..], [Ok(0), Ok(1), Ok(2), Ok(3), Ok(4)]);
    }

    /// A type to use when we don't actually plan for the Future to succeed.
    type FutureReturningATonicLikeStreamOf<T> = std::future::Ready<
        tonic::Result<tonic::Response<futures_util::stream::Pending<tonic::Result<T>>>>,
    >;

    #[test]
    fn test_stream_with_invalid_request() {
        let stream = send_request_with_streaming_response(
            "test",
            (),
            || Err(RequestError::Other(TestError::Expected)),
            |_, _: ()| -> FutureReturningATonicLikeStreamOf<()> { unreachable!() },
            |_: ()| -> StreamResult<(), TestError> { unreachable!() },
            |_| unreachable!(),
        );
        let contents: Vec<_> = stream.collect().now_or_never().expect("ready");
        assert_matches!(
            &contents[..],
            [Err(RequestError::Other(TestError::Expected))]
        );
    }

    #[test]
    fn test_stream_with_failed_send() {
        let stream = send_request_with_streaming_response(
            "test",
            (),
            || Ok(()),
            |_, _| -> FutureReturningATonicLikeStreamOf<()> {
                std::future::ready(Err(tonic::Status::permission_denied("potential user data")))
            },
            |_: ()| -> StreamResult<(), TestError> { unreachable!() },
            |_| unreachable!(),
        );
        let contents: Vec<_> = stream.collect().now_or_never().expect("ready");
        assert_matches!(
            &contents[..],
            [Err(RequestError::Unexpected { log_safe })]
            if log_safe.contains("PermissionDenied") && !log_safe.contains("user data")
        );
    }

    #[test]
    fn test_stream_with_server_side_error_on_send() {
        let stream = send_request_with_streaming_response(
            "test",
            (),
            || Ok(()),
            |_, _| -> FutureReturningATonicLikeStreamOf<()> {
                std::future::ready(Err(status_for_server_side_error(
                    tonic::Code::Aborted,
                    "STREAM_CLOSED",
                    Vec::<()>::new(),
                )))
            },
            |_: ()| -> StreamResult<(), TestError> { unreachable!() },
            |_status| Err(RequestError::Other(TestError::Expected)),
        );
        let contents: Vec<_> = stream.collect().now_or_never().expect("ready");
        assert_matches!(
            &contents[..],
            [Err(RequestError::Other(TestError::Expected))]
        );
    }

    #[test]
    fn test_stream_with_bad_item() {
        let stream = send_request_with_streaming_response(
            "test",
            0u32,
            || Ok(U32Request(5)),
            |start: u32, U32Request(finish)| {
                let contents =
                    futures_util::stream::iter(start..finish).map(|i| Ok(i.to_le_bytes()));
                std::future::ready(Ok(tonic::Response::from(contents)))
            },
            |next| {
                let result = u32::from_le_bytes(next);
                if result < 3 {
                    Ok(result)
                } else {
                    Err(RequestError::Other(TestError::Expected))
                }
            },
            |_| unreachable!(),
        );

        let contents = collect_up_to_and_including_first_error(stream)
            .now_or_never()
            .expect("ready");

        assert_matches!(
            &contents[..],
            [
                Ok(0),
                Ok(1),
                Ok(2),
                Err(RequestError::Other(TestError::Expected))
            ]
        );
    }

    #[test]
    fn test_stream_with_grpc_error() {
        let stream = send_request_with_streaming_response(
            "test",
            0u32,
            || Ok(U32Request(5)),
            |start: u32, U32Request(finish)| {
                let contents = futures_util::stream::iter(start..finish)
                    .map(|i| Ok(i.to_le_bytes()))
                    .chain(futures_util::stream::iter([Err(
                        tonic::Status::permission_denied("potential user data"),
                    )]));
                std::future::ready(Ok(tonic::Response::from(contents)))
            },
            |next| Ok(u32::from_le_bytes(next)),
            |_status| Err(RequestError::Other(TestError::Expected)),
        );

        let contents: Vec<_> = stream.collect().now_or_never().expect("ready");
        assert_matches!(
            &contents[..],
            [
                Ok(0),
                Ok(1),
                Ok(2),
                Ok(3),
                Ok(4),
                Err(RequestError::Unexpected { log_safe }),
            ]
            if log_safe.contains("PermissionDenied") && !log_safe.contains("user data")
        );
    }

    #[test]
    fn test_stream_with_server_side_error() {
        let stream = send_request_with_streaming_response(
            "test",
            0u32,
            || Ok(U32Request(5)),
            |start: u32, U32Request(finish)| {
                let contents = futures_util::stream::iter(start..finish)
                    .map(|i| Ok(i.to_le_bytes()))
                    .chain(futures_util::stream::iter([Err(
                        status_for_server_side_error(
                            tonic::Code::Aborted,
                            "STREAM_CLOSED",
                            Vec::<()>::new(),
                        ),
                    )]));
                std::future::ready(Ok(tonic::Response::from(contents)))
            },
            |next| Ok(u32::from_le_bytes(next)),
            |_status| Err(RequestError::Other(TestError::Expected)),
        );

        let contents: Vec<_> = stream.collect().now_or_never().expect("ready");
        assert_matches!(
            &contents[..],
            [
                Ok(0),
                Ok(1),
                Ok(2),
                Ok(3),
                Ok(4),
                Err(RequestError::Other(TestError::Expected))
            ]
        );
    }
}
