//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use boring_signal::ssl::SslRef;
use http::{HeaderName, HeaderValue};
use tokio_boring_signal::HandshakeError;

use crate::{AsStaticHttpHeader, certs};

pub trait LogSafeDisplay: Display {
    /// Assert that this type implements `LogSafeDisplay`
    fn log_safe_display(&self) -> &Self
    where
        Self: Sized,
    {
        self
    }
}

/// Vacuous implementation since you can't actually [`Display::fmt`] a
/// [`std::convert::Infallible`].
impl LogSafeDisplay for std::convert::Infallible {}

#[derive(Copy, Clone, Debug, thiserror::Error, displaydoc::Display)]
/// retry after {retry_after_seconds}s
pub struct RetryLater {
    pub retry_after_seconds: u32,
}

/// Errors that can occur during transport-level connection establishment.
#[derive(displaydoc::Display, Debug, thiserror::Error)]
pub enum TransportConnectError {
    /// Invalid configuration for this connection
    InvalidConfiguration,
    /// Failed to establish TCP connection to any of the IPs
    TcpConnectionFailed,
    /// SSL error: {0}
    SslError(SslErrorReasons),
    /// Failed to load certificates
    CertError,
    /// Failed to establish SSL connection: {0}
    SslFailedHandshake(FailedHandshakeReason),
    /// Proxy handshake failed
    ProxyProtocol,
    /// Abort due to local error
    ClientAbort,
}
impl LogSafeDisplay for TransportConnectError {}

#[derive(Debug)]
pub struct SslErrorReasons(boring_signal::error::ErrorStack);

impl Display for SslErrorReasons {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.errors().iter().map(|e| {
                // We'd like to use e.reason(), but that might have user data in it.
                format!(
                    "{} error {}",
                    e.library().unwrap_or("unknown"),
                    e.library_code(),
                )
            }))
            .finish()
    }
}

type X509CertSha256 = [u8; 32];

#[derive(Debug, PartialEq)]
pub enum FailedHandshakeReason {
    Io(std::io::ErrorKind),
    Cert {
        error: boring_signal::x509::X509VerifyError,
        cert_hashes: Vec<X509CertSha256>,
    },
    OtherBoring(boring_signal::ssl::ErrorCode),
}

// Coarse check for user data in the BoringSSL error code types.
// This isn't perfect---an IP address is Copy---but it'll catch Strings and Vecs at least.
static_assertions::assert_impl_all!(boring_signal::x509::X509VerifyError: Copy);
static_assertions::assert_impl_all!(boring_signal::ssl::ErrorCode: Copy);

impl FailedHandshakeReason {
    pub const TIMED_OUT: Self = Self::Io(std::io::ErrorKind::TimedOut);

    pub fn is_possible_captive_network(&self) -> bool {
        matches!(
            self,
            Self::Cert {
                error: boring_signal::x509::X509VerifyError::SELF_SIGNED_CERT_IN_CHAIN
                    | boring_signal::x509::X509VerifyError::DEPTH_ZERO_SELF_SIGNED_CERT,
                cert_hashes: _,
            }
        )
    }
}

/// Error type for TLS handshake timeouts
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("TLS handshake timed out")]
pub struct TlsHandshakeTimeout;

/// Produce a `Vec` of SHA256 fingerprints of the cert chain
///
/// We only use this in logging, so errors just translate into an empty `Vec` (or an all zero hash).
fn ssl_peer_cert_chain(ssl: &SslRef) -> Vec<X509CertSha256> {
    ssl.peer_cert_chain()
        .map(|chain| {
            chain
                .iter()
                .map(|cert| {
                    cert.digest(boring_signal::hash::MessageDigest::sha256())
                        .ok()
                        .map(|digest| {
                            X509CertSha256::try_from(&*digest).expect("SHA-256 is 32 bytes")
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default()
}

impl<S> From<HandshakeError<S>> for FailedHandshakeReason {
    fn from(value: HandshakeError<S>) -> Self {
        log::debug!("handshake error: {value}");

        // Prefer IO errors over Boring errors; the IO error will likely be more specific.
        if let Some(io) = value.as_io_error().map(std::io::Error::kind) {
            return Self::Io(io);
        }

        let code = value.code().unwrap_or(boring_signal::ssl::ErrorCode::NONE);

        // If we specifically have an *SSL* error, check if it's an *X509* error underneath.
        // (But not X509VerifyError::INVALID_CALL, which means we're not in the right state to
        // query for verification errors.)
        if code == boring_signal::ssl::ErrorCode::SSL
            && let Some(cert_error_code) = value.ssl().and_then(|ssl| ssl.verify_result().err())
            && cert_error_code != boring_signal::x509::X509VerifyError::INVALID_CALL
        {
            // NB: peer_cert_chain() contains the server cert.
            return Self::Cert {
                error: cert_error_code,
                cert_hashes: value.ssl().map(ssl_peer_cert_chain).unwrap_or_default(),
            };
        }

        Self::OtherBoring(code)
    }
}

impl LogSafeDisplay for FailedHandshakeReason {}
impl Display for FailedHandshakeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtherBoring(boring_signal::ssl::ErrorCode::NONE) => write!(f, "unknown error"),
            Self::Io(error_kind) => write!(f, "IO error: {error_kind}"),
            Self::Cert {
                error: code,
                cert_hashes,
            } => {
                write!(
                    f,
                    "boring X509 error code: {} {}, cert_chain: ",
                    code.as_raw(),
                    code.error_string()
                )?;
                f.debug_list()
                    .entries(cert_hashes.iter().map(|hash| BASE64_STANDARD.encode(hash)))
                    .finish()
            }
            Self::OtherBoring(code) => write!(f, "boring SSL error code: {}", code.as_raw()),
        }
    }
}

impl RetryLater {
    /// The amount of time to wait before retrying, as a [`Duration`].
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.retry_after_seconds.into())
    }
}

impl AsStaticHttpHeader for RetryLater {
    const HEADER_NAME: HeaderName = HeaderName::from_static("retry-after");

    fn header_value(&self) -> HeaderValue {
        HeaderValue::from(self.retry_after_seconds)
    }
}

impl From<boring_signal::error::ErrorStack> for TransportConnectError {
    fn from(value: boring_signal::error::ErrorStack) -> Self {
        Self::SslError(SslErrorReasons(value))
    }
}

impl From<certs::Error> for TransportConnectError {
    fn from(_value: certs::Error) -> Self {
        Self::CertError
    }
}

impl<S> From<HandshakeError<S>> for TransportConnectError {
    fn from(error: HandshakeError<S>) -> Self {
        Self::SslFailedHandshake(FailedHandshakeReason::from(error))
    }
}

impl From<TransportConnectError> for std::io::Error {
    fn from(value: TransportConnectError) -> Self {
        use std::io::ErrorKind;
        let kind = match value {
            TransportConnectError::InvalidConfiguration => ErrorKind::InvalidInput,
            TransportConnectError::TcpConnectionFailed => ErrorKind::ConnectionRefused,
            TransportConnectError::SslFailedHandshake(_)
            | TransportConnectError::SslError(_)
            | TransportConnectError::CertError
            | TransportConnectError::ProxyProtocol => ErrorKind::InvalidData,
            TransportConnectError::ClientAbort => ErrorKind::ConnectionAborted,
        };
        Self::new(kind, value.to_string())
    }
}

impl From<TlsHandshakeTimeout> for TransportConnectError {
    fn from(TlsHandshakeTimeout: TlsHandshakeTimeout) -> Self {
        Self::SslFailedHandshake(FailedHandshakeReason::TIMED_OUT)
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::num::NonZero;

    use futures_util::future::Either;

    use crate::OverrideNagleAlgorithm;
    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::route::{ComposedConnector, ConnectorExt, TcpRoute, TlsRoute, TlsRouteFragment};
    use crate::tcp_ssl::testutil::{
        SERVER_CERTIFICATE, SERVER_HOSTNAME, simple_localhost_https_server,
    };
    use crate::tcp_ssl::{StatelessTcp, StatelessTls};

    #[test_log::test(tokio::test)]
    async fn consistent_cert_hashes() {
        let mut cert_hashes = Vec::new();
        for _ in 0..2 {
            let (addr, server) = simple_localhost_https_server();
            let server = Box::pin(server);
            type StatelessTlsConnector = ComposedConnector<StatelessTls, StatelessTcp>;
            let connector = StatelessTlsConnector::default();
            let client = Box::pin(
                connector.connect(
                    TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::FromDer(Cow::Borrowed(
                                SERVER_CERTIFICATE.cert.der(),
                            )),
                            sni: Host::Domain(SERVER_HOSTNAME.into()),
                            alpn: None,
                            min_protocol_version: None,
                        },
                        inner: TcpRoute {
                            address: addr.ip(),
                            port: NonZero::new(addr.port())
                                .expect("successful listener has a valid port"),
                            override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                        },
                    },
                    "transport",
                ),
            );
            let (stream, _server) = match futures_util::future::select(client, server).await {
                Either::Left((stream, server)) => (stream.expect("successful connection"), server),
                Either::Right(_) => panic!("server exited unexpectedly"),
            };
            cert_hashes.push(super::ssl_peer_cert_chain(stream.ssl()));
        }
        assert_eq!(cert_hashes[0], cert_hashes[1]);
    }
}
