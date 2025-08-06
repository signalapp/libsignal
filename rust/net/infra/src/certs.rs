//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::sync::{Arc, OnceLock};

use boring_signal::error::ErrorStack;
use boring_signal::ssl::{SslAlert, SslConnectorBuilder, SslVerifyMode};
use boring_signal::x509::store::X509StoreBuilder;
use boring_signal::x509::X509;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};

use crate::dns::dns_utils::log_safe_domain;
use crate::errors::LogSafeDisplay;
use crate::host::Host;

mod error;

#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum Error {
    /// Bad certificate
    BadCertificate,
    /// Bad hostname
    BadHostname,
}

impl From<ErrorStack> for Error {
    fn from(_value: ErrorStack) -> Self {
        Self::BadCertificate
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RootCertificates {
    Native,
    FromStaticDers(&'static [&'static [u8]]),
    FromDer(Cow<'static, [u8]>),
}

impl RootCertificates {
    /// Configures `connector` to verify certificates against `self`.
    ///
    /// **Warning:** If `self` is [`RootCertificates::Native`], the resulting connector will
    /// **depend on tokio** to verify certificates (using rustls-platform-verifier, isolated to a
    /// blocking task thread). Moreover, when using the resulting [`boring::ssl::Ssl`] object, you
    /// must call `set_task_waker`. This will be taken care of for you if you use tokio-boring (and
    /// always poll within a tokio context).
    pub fn apply_to_connector(
        &self,
        connector: &mut SslConnectorBuilder,
        host: Host<&str>,
    ) -> Result<(), Error> {
        let ders: &[&[u8]] = match self {
            RootCertificates::Native => {
                static VERIFIER: OnceLock<Box<dyn LimitedServerCertVerifier>> = OnceLock::new();

                let verifier = VERIFIER.get_or_init(|| {
                    let mut verifier = rustls_platform_verifier::Verifier::new();
                    if cfg!(target_os = "linux")
                        && rustls::crypto::CryptoProvider::get_default().is_none()
                    {
                        // On Linux rustls-platform-verifier uses the webpki crate, which requires a
                        // rustls CryptoProvider. On the other platforms, rustls-platform-verifier ought
                        // to work even with no provider set, so we omit this to avoid taking a
                        // dependency on ring.
                        verifier.set_provider(rustls::crypto::ring::default_provider().into())
                    }

                    if cfg!(target_os = "android") {
                        // rustls-platform-verifier's Android code permanently
                        // attaches the thread that makes the verification calls
                        // to the JVM. Use an implementation that calls into
                        // verification code on a background thread to prevent
                        // the current thread from being attached to the JVM.
                        //
                        // See https://github.com/rustls/rustls-platform-verifier/issues/184
                        return Box::new(BackgroundThreadVerifier::new(verifier));
                    }

                    Box::new(verifier)
                });
                return set_up_platform_verifier(connector, host, &**verifier);
            }
            RootCertificates::FromStaticDers(ders) => ders,
            RootCertificates::FromDer(der) => &[der],
        };
        let mut store_builder = X509StoreBuilder::new()?;
        for der in ders {
            store_builder.add_cert(X509::from_der(der)?)?;
        }
        connector.set_verify_cert_store(store_builder.build())?;
        Ok(())
    }
}

/// A subset of [`ServerCertVerifier`] that only exposes
/// [`verify_server_cert`](ServerCertVerifier::verify_server_cert).
///
/// This is blanket-implemented for `ServerCertVerifier`.
trait LimitedServerCertVerifier: Send + Sync {
    fn verify_server_cert(
        &self,
        end_entity: CertificateDer<'_>,
        intermediates: Vec<CertificateDer<'_>>,
        server_name: &ServerName<'_>,
    ) -> Result<ServerCertVerified, rustls::Error>;
}

impl<V: ServerCertVerifier> LimitedServerCertVerifier for V {
    fn verify_server_cert(
        &self,
        end_entity: CertificateDer<'_>,
        intermediates: Vec<CertificateDer<'_>>,
        server_name: &ServerName<'_>,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // We don't do our own OCSP. Either the platform will do its own checks, or it won't.
        let ocsp_response = [];

        ServerCertVerifier::verify_server_cert(
            self,
            &end_entity,
            &intermediates,
            server_name,
            &ocsp_response,
            rustls::pki_types::UnixTime::now(),
        )
    }
}

impl LimitedServerCertVerifier for &dyn LimitedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: CertificateDer<'_>,
        intermediates: Vec<CertificateDer<'_>>,
        server_name: &ServerName<'_>,
    ) -> Result<ServerCertVerified, rustls::Error> {
        (**self).verify_server_cert(end_entity, intermediates, server_name)
    }
}

/// Configures [rustls_platform_verifier] as a BoringSSL (async) custom verify callback.
///
/// We make it async because the platform verification can do unbounded work (on Android we have
/// observed it doing network activity!)
///
/// Note that `connector` will **depend on tokio** to verify certificates. Moreover, when using the
/// resulting [`boring::ssl::Ssl`] object, you must call `set_task_waker`. This will be taken care
/// of for you if you use tokio-boring (and always poll within a tokio context).
fn set_up_platform_verifier(
    connector: &mut SslConnectorBuilder,
    host: Host<&str>,
    verifier: impl LimitedServerCertVerifier + 'static,
) -> Result<(), Error> {
    let host_as_server_name = match host {
        Host::Domain(host_name) => ServerName::try_from(host_name)
            .map_err(|_| Error::BadHostname)?
            .to_owned(),
        Host::Ip(ip) => ServerName::IpAddress(ip.into()),
    };

    // Ideally we wouldn't need to wrap these in Arcs, but Rust doesn't understand spawn_blocking
    // immediately followed by await.
    let verifier = Arc::new(verifier);
    let host_as_server_name = Arc::new(host_as_server_name);

    // For maximum generality, this is a *function* that returns a *future* that returns a
    // *function.* We do as much checking up front as we can before spawning the
    // potentially-blocking work, but then after that we just return the result directly.
    connector.set_async_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        // Get the certificate chain, lazily convert each certificate to DER (as expected by rustls).
        let mut cert_chain = ssl
            .peer_cert_chain()
            .ok_or(SslAlert::NO_CERTIFICATE)?
            .into_iter()
            .map(|cert| Ok(cert.to_der()?.into()));

        // The head of the chain should be the leaf certificate.
        let end_entity = match cert_chain.next() {
            Some(Ok(leaf_cert)) => leaf_cert,
            None | Some(Err(_)) => {
                return Err(SslAlert::BAD_CERTIFICATE);
            }
        };

        // The rest of the chain should be valid intermediate certificates.
        let intermediates: Vec<CertificateDer<'_>> = cert_chain
            .collect::<Result<_, boring_signal::error::ErrorStack>>()
            .map_err(|_| SslAlert::BAD_CERTIFICATE)?;

        // Borrow these for the nested task. Ideally this wouldn't require refcounting, but Rust
        // doesn't understand spawn_blocking immediately followed by await.
        let verifier = verifier.clone();
        let host_as_server_name = host_as_server_name.clone();

        let task = tokio::task::spawn_blocking(move || -> Result<(), SslAlert> {
            verifier
                .verify_server_cert(end_entity, intermediates, &host_as_server_name)
                .map_err(|e| {
                    // The most important thing is to reject the certificate. Mapping the errors over
                    // only affects what message gets reported in logs. Which isn't *unimportant*, but
                    // isn't critical for correctness either.
                    //
                    // From RFC 5246:
                    // - bad_certificate: A certificate was corrupt, contained signatures that did not
                    //   verify correctly, etc.
                    // - certificate_expired: A certificate has expired or is not currently valid.
                    // - certificate_unknown: Some other (unspecified) issue arose in processing the
                    //   certificate, rendering it unacceptable.
                    // - certificate_revoked: A certificate was revoked by its signer.
                    // - unknown_ca: A valid certificate chain or partial chain was received, but the
                    //   certificate was not accepted because the CA certificate could not be located or
                    //   couldn't be matched with a known, trusted CA.
                    // - internal_error: An internal error unrelated to the peer or the correctness of
                    //   the protocol (such as a memory allocation failure) makes it impossible to
                    //   continue.
                    log::info!(
                        "TLS certificate for {} failed verification: {}",
                        log_safe_domain(&host_as_server_name.to_str()),
                        (&error::LogSafeTlsError(&e) as &dyn LogSafeDisplay)
                    );
                    match e {
                        rustls::Error::InvalidCertificate(e) => match e {
                            rustls::CertificateError::BadEncoding => SslAlert::BAD_CERTIFICATE,
                            rustls::CertificateError::Expired => SslAlert::CERTIFICATE_EXPIRED,
                            rustls::CertificateError::NotValidYet => SslAlert::CERTIFICATE_UNKNOWN,
                            rustls::CertificateError::Revoked => SslAlert::CERTIFICATE_REVOKED,
                            rustls::CertificateError::UnhandledCriticalExtension => {
                                SslAlert::CERTIFICATE_UNKNOWN
                            }
                            rustls::CertificateError::UnknownIssuer => SslAlert::UNKNOWN_CA,
                            rustls::CertificateError::UnknownRevocationStatus => {
                                SslAlert::CERTIFICATE_UNKNOWN
                            }
                            rustls::CertificateError::BadSignature => SslAlert::BAD_CERTIFICATE,
                            rustls::CertificateError::NotValidForName => {
                                SslAlert::CERTIFICATE_UNKNOWN
                            }
                            rustls::CertificateError::InvalidPurpose => {
                                SslAlert::CERTIFICATE_UNKNOWN
                            }
                            rustls::CertificateError::ApplicationVerificationFailure => {
                                SslAlert::INTERNAL_ERROR
                            }
                            rustls::CertificateError::Other(_) => SslAlert::CERTIFICATE_UNKNOWN,

                            // CertificateError is marked non_exhaustive, so we also have to have an explicit fallback:
                            _ => SslAlert::CERTIFICATE_UNKNOWN,
                        },
                        _ => SslAlert::BAD_CERTIFICATE,
                    }
                })?;
            Ok(())
        });

        Ok(Box::pin(async move {
            task.await.unwrap_or(Err(SslAlert::INTERNAL_ERROR))?;

            // Remember, our future is supposed to return...another function. We don't have any
            // post-platform-verifier work to take care of, though, so our function will just return
            // Ok(()) all the time.
            // The explicit reference here seems to be necessary to convince Rust that we
            // aren't going to use the lifetime of the final argument at all.
            Ok(Box::new(|_: &mut _| Ok(())) as boring_signal::ssl::BoxCustomVerifyFinish)
        }))
    });

    Ok(())
}

/// [`LimitedServerCertVerifier`] that runs verification on a background thread.
struct BackgroundThreadVerifier {
    sender: std::sync::mpsc::SyncSender<(VerifyContext, BackgroundResultSender)>,
}

const MAX_QUEUED_VERIFICATIONS: usize = 8;

type BackgroundResultSender =
    tokio::sync::oneshot::Sender<Result<ServerCertVerified, rustls::Error>>;

impl BackgroundThreadVerifier {
    fn new(verifier: impl LimitedServerCertVerifier + 'static) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<(VerifyContext, BackgroundResultSender)>(
            MAX_QUEUED_VERIFICATIONS,
        );
        let _thread = std::thread::spawn(move || {
            while let Ok((context, result_sender)) = rx.recv() {
                let VerifyContext {
                    end_entity,
                    intermediates,
                    server_name,
                } = context;
                let result = verifier.verify_server_cert(end_entity, intermediates, &server_name);

                let _ignore_failed_send = result_sender.send(result);
            }
        });

        Self { sender: tx }
    }
}

/// [`Send`]able package of values that [BackgroundThreadVerifier] pushes to its worker thread
struct VerifyContext {
    end_entity: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
    server_name: ServerName<'static>,
}

impl LimitedServerCertVerifier for BackgroundThreadVerifier {
    fn verify_server_cert(
        &self,
        end_entity: CertificateDer<'_>,
        intermediates: Vec<CertificateDer<'_>>,
        server_name: &ServerName<'_>,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Self { sender } = self;

        let (result_tx, result_rx) = tokio::sync::oneshot::channel();

        let context = VerifyContext {
            end_entity: end_entity.clone().into_owned(),
            intermediates: intermediates
                .into_iter()
                .map(CertificateDer::into_owned)
                .collect(),
            server_name: server_name.to_owned(),
        };
        sender
            .send((context, result_tx))
            .expect("Verifier thread is unexpectedly no longer available");

        result_rx
            .blocking_recv()
            .map_err(|_recv| rustls::Error::General("worker thread failed".to_owned()))?
    }
}

#[cfg(test)]
mod test {
    use std::convert::identity;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use boring_signal::ssl::{ErrorCode, SslConnector, SslMethod};
    use rustls::RootCertStore;
    use tokio::net::TcpStream;

    use super::*;
    use crate::tcp_ssl::proxy::testutil::PROXY_CERTIFICATE;
    use crate::tcp_ssl::testutil::{
        localhost_https_server, make_http_request_response_over, SERVER_CERTIFICATE,
        SERVER_HOSTNAME,
    };

    impl LimitedServerCertVerifier for Box<dyn LimitedServerCertVerifier> {
        fn verify_server_cert(
            &self,
            end_entity: CertificateDer<'_>,
            intermediates: Vec<CertificateDer<'_>>,
            server_name: &ServerName<'_>,
        ) -> Result<ServerCertVerified, rustls::Error> {
            (**self).verify_server_cert(end_entity, intermediates, server_name)
        }
    }

    fn on_background_thread(
        verifier: Box<dyn LimitedServerCertVerifier>,
    ) -> Box<dyn LimitedServerCertVerifier> {
        Box::new(BackgroundThreadVerifier::new(verifier))
    }

    #[test_case::test_case(identity)]
    #[test_case::test_case(on_background_thread)]
    #[tokio::test]
    async fn verify_certificate_via_rustls(
        make_verifier: fn(Box<dyn LimitedServerCertVerifier>) -> Box<dyn LimitedServerCertVerifier>,
    ) {
        let (addr, server) = localhost_https_server();
        let _server_handle = tokio::spawn(server);

        let mut root_cert_store = RootCertStore::empty();
        root_cert_store
            .add(SERVER_CERTIFICATE.cert.der().clone())
            .expect("valid");
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_cert_store))
            .build()
            .expect("valid");

        let mut ssl = SslConnector::builder(SslMethod::tls_client()).expect("valid");
        let verifier = Arc::into_inner(verifier).expect("only one referent");
        let verifier = make_verifier(Box::new(verifier));
        set_up_platform_verifier(&mut ssl, Host::Domain(SERVER_HOSTNAME), verifier).expect("valid");

        let transport = TcpStream::connect(addr).await.expect("can connect");
        let connection = tokio_boring_signal::connect(
            ssl.build().configure().expect("valid"),
            SERVER_HOSTNAME,
            transport,
        )
        .await
        .expect("successful handshake");

        make_http_request_response_over(connection)
            .await
            .expect("no errors");
    }

    #[test_case::test_case(identity)]
    #[test_case::test_case(on_background_thread)]
    #[tokio::test]
    async fn verify_certificate_failure_via_rustls(
        make_verifier: fn(Box<dyn LimitedServerCertVerifier>) -> Box<dyn LimitedServerCertVerifier>,
    ) {
        let (addr, server) = localhost_https_server();
        let _server_handle = tokio::spawn(server);

        let mut root_cert_store = RootCertStore::empty();
        // Wrong certificate here!
        root_cert_store
            .add(PROXY_CERTIFICATE.cert.der().clone())
            .expect("valid");
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_cert_store))
            .build()
            .expect("valid");

        let mut ssl = SslConnector::builder(SslMethod::tls_client()).expect("valid");
        let verifier = Arc::into_inner(verifier).expect("only one referent");
        let verifier = make_verifier(Box::new(verifier));
        set_up_platform_verifier(&mut ssl, Host::Domain(SERVER_HOSTNAME), verifier).expect("valid");

        let transport = TcpStream::connect(addr).await.expect("can connect");
        assert_matches!(
            tokio_boring_signal::connect(
                ssl.build().configure().expect("valid"),
                SERVER_HOSTNAME,
                transport,
            )
            .await,
            Err(e) if e.code() == Some(ErrorCode::SSL)
        );
    }
}
