//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `grpc` module and its submodules implement a chat server based on the gRPC messages from
//! [libsignal-net-grpc](libsignal_net_grpc).

mod usernames;

use std::future::Future;

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
trait GrpcServiceProvider: Sync {
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

/// Converts a standard gRPC error code into a RequestError.
///
/// This should only be used after any processing of request-specific codes.
fn into_default_request_error<E>(status: tonic::Status) -> RequestError<E> {
    match status.code() {
        // TODO: Use ServerSideError for some of the codes if the metadata says it was sent by the
        // server at the application level. Unfortunately we can't distinguish between server-side
        // gRPC library errors and client-side gRPC library errors.
        tonic::Code::DeadlineExceeded => return RequestError::Timeout,
        tonic::Code::Unavailable => return RequestError::Disconnected(DisconnectedError::Closed),

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

#[cfg(test)]
mod testutil {
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
