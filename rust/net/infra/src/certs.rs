//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::sync::{Arc, LazyLock, OnceLock};

use boring_signal::error::ErrorStack;
use boring_signal::hash::{MessageDigest, hash};
use boring_signal::pkey::{PKey, Public};
use boring_signal::ssl::{SslAlert, SslConnectorBuilder, SslVerifyMode};
use boring_signal::x509::store::X509StoreBuilder;
use boring_signal::x509::{X509, X509Ref};
use futures_util::future::BoxFuture;
use libsignal_core::LogSafeDisplay;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};

use crate::dns::dns_utils::log_safe_domain;
use crate::host::Host;

mod error;

#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum Error {
    /// Bad certificate
    BadCertificate,
    /// Bad hostname
    BadHostname,
}

type SpkiSha256 = [u8; 32];

// Distrusted SPKIs for weak intermediate certs from
// https://github.com/rustls/webpki/commit/f3caaa9f2ba94a42dcd31767e367688a416a3d87
// The Android platform verifier keeps a copy of this list in
// java/android/src/main/java/org/rustls/platformverifier/CertificateVerifier.kt.
const DISTRUSTED_EMUDHRA_SPKI_SHA256: &[SpkiSha256] = &[
    // EMDVTLSCAG3B
    const_str::hex!("ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105"),
    // EMDVTLSCAG3C
    const_str::hex!("49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f"),
    // EMEVTLSCAG3B
    const_str::hex!("e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41"),
    // EMEVTLSCAG3C
    const_str::hex!("5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0"),
    // EMOVCSCAG3B
    const_str::hex!("ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6"),
    // EMOVCSCAG3C
    const_str::hex!("92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30"),
    // EMOVTLSCAG3B
    const_str::hex!("43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b"),
    // EMOVTLSCAG3C
    const_str::hex!("63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8"),
];

const DISTRUSTED_EMUDHRA_SPKIS: &[&[u8]] = &[
    // EMDVTLSCAG3B
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b8104002203620004e79ed9c04a9773c4735e51111da85ac2bd5e64ab374b80e12cbc2038ec1e4f0e3b812fc9859e1e67afb04e2f8bc97f7485ba65aa911ee8a4e45b62d5cc03d56be678b3c38cb4dc937ca2460e238453c892935d29d44f91e15606b63ccedab468"
    ),
    // EMDVTLSCAG3C
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b81040022036200043a7a7862c8c44d324ddd69033a6782c0efeefe4055e68a123fa0371ba3bd9194514ee172a433e3630f02bd188037d9e5149f9b77db94a281df987b2fea888b74bdfe8fda4c1099ee6ca19566fe3ef0e5f6b09a556ccc8ba50561df1b2a441d01"
    ),
    // EMEVTLSCAG3B
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b810400220362000425dba85a64d397da0b1052e9ea546e487befea9c9d9d68a0c5eadcfeef75a69bb5d6fc01f42bfbca6eb40bcd64c0767e36ffd05d97a813c5aa0c6c9530e79cf5f0866468f13806420aa5c851840b1e252540e790e4b654c3852ed64af1e8657d"
    ),
    // EMEVTLSCAG3C
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b81040022036200042d56e829a6fb82c64a4697d960af951e9067ae91f926d34306da48a8aaeb7869b6a67e6d27426e0442aa03b36e1988dff636514ee1cf07f5ba4b3ff2a06645ae7d31d5866ad31aa3d246eb0b3177ee99cb7566c516ce74808a668f91f0c47fca"
    ),
    // EMOVCSCAG3B
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b8104002203620004aabb0fb0666acfcf01fad52bfcfd4c2bf2cb3c3497de73950e5819b61fe695098741c8c491439b34a0431caffe5bf9b4c1c8e8ae0001f9f4dc8ad82c59f3639e96cd6c3d4db0cefec26c3d62517b37761372743f8e8add77b10064f2abe5e050"
    ),
    // EMOVCSCAG3C
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b8104002203620004b9f0e0634702a69ca6aadd443cfd62c41b9ba4b20924697d7974e7691a126fb96afb3e34c2fd3bc5f483061f265dc2a58436347323510436b28f04f3862363067980e2503e02532d6546235a7165a259a1ef496f741b5fdee7787208e4b8faef"
    ),
    // EMOVTLSCAG3B
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b810400220362000473897aa0eb3cfdca8b12402ffaf0abc4e1212baf8dee778ac9ee2d6db83fac280c5e05638ae7a2acd71c322a8e361cdeb9f69c4302b9dd8d73d1cc6caab2cc0aee4e216ce979dd518a4af4b626e5684cdd658037ed0c854e4cc12f4cf8646d0d"
    ),
    // EMOVTLSCAG3C
    &const_str::hex!(
        "3076301006072a8648ce3d020106052b8104002203620004138251cd52ac9298c1c8aad977321deb97e709bd0b4ca0aca55dc8ad51dcfc9d1589a1597e3a5120e1efd631c63e1835cacae29869a62e1631e8a28181ab56616dc45d918abc09f3ab0e63cf792aa4dced7387be37bba569549f1c02b270ed67"
    ),
];

static DISTRUSTED_EMUDHRA_KEYS: LazyLock<Vec<PKey<Public>>> = LazyLock::new(|| {
    DISTRUSTED_EMUDHRA_SPKIS
        .iter()
        .map(|der| PKey::public_key_from_der(der).expect("valid hard-coded eMudhra SPKI"))
        .collect()
});

fn uses_distrusted_emudhra_key(cert: &X509Ref) -> Result<bool, ErrorStack> {
    // First, check whether this certificate contains one of the compromised public keys. This
    // catches the usual case where the server sends the compromised intermediate in its chain.
    let spki = cert.public_key()?.public_key_to_der()?;
    let digest = hash(MessageDigest::sha256(), &spki)?;
    if DISTRUSTED_EMUDHRA_SPKI_SHA256
        .iter()
        .any(|distrusted| distrusted.as_slice() == digest.as_ref())
    {
        return Ok(true);
    }

    // The server can omit the intermediate because a native verifier may find it in a local cache
    // or fetch it over AIA. In that case BoringSSL only gives us the leaf:
    //
    //     trusted root -> compromised intermediate -> leaf
    //
    // Each affected intermediate has a path length constraint of zero, so it can only sign leaves,
    // not another intermediate. If this certificate's signature verifies with a compromised public
    // key, it is such a leaf and must be rejected even though its issuer was omitted.
    for key in DISTRUSTED_EMUDHRA_KEYS.iter() {
        let signed_by_key = cert.verify(key)?;
        // X509_verify reports a non-matching key by returning false *and* pushing an error onto
        // BoringSSL's thread-local error queue. SSL_get_error checks that queue before the I/O
        // state, so a leftover entry would make the handshake's next would-block step (WANT_READ,
        // or WANT_CERTIFICATE_VERIFY while the platform verifier runs) look like a fatal error.
        // Drain the queue after every call so the handshake only ever sees its own errors. See
        // x509_verify_mismatch_leaves_errors_in_boringssl_error_queue in the tests below.
        drop(ErrorStack::get());
        if signed_by_key {
            return Ok(true);
        }
    }
    Ok(false)
}

impl From<ErrorStack> for Error {
    fn from(_value: ErrorStack) -> Self {
        Self::BadCertificate
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
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
    /// blocking task thread). Moreover, when using the resulting [`Ssl`](boring_signal::ssl::Ssl)
    /// object, you must call `set_task_waker`. This will be taken care of for you if you use
    /// tokio-boring (and always poll within a tokio context).
    pub fn apply_to_connector(
        &self,
        connector: &mut SslConnectorBuilder,
        host: Host<&str>,
    ) -> Result<(), Error> {
        let ders: &[&[u8]] = match self {
            RootCertificates::Native => {
                static VERIFIER: OnceLock<Box<dyn LimitedServerCertVerifier>> = OnceLock::new();

                let verifier = VERIFIER.get_or_init(|| {
                    let crypto_provider = if cfg!(target_os = "linux") {
                        // On Linux rustls-platform-verifier uses the webpki crate, which requires a
                        // rustls CryptoProvider. On the other platforms, rustls-platform-verifier ought
                        // to work even with no provider set, so we omit this to avoid taking a
                        // dependency on ring.
                        rustls::crypto::ring::default_provider()
                    } else {
                        rustls::crypto::CryptoProvider {
                            cipher_suites: vec![],
                            kx_groups: vec![],
                            signature_verification_algorithms:
                                rustls::crypto::WebPkiSupportedAlgorithms {
                                    all: &[],
                                    mapping: &[],
                                },
                            secure_random: &UnimplementedRustlsSecureRandom,
                            key_provider: &UnimplementedRustlsKeyProvider,
                        }
                    };
                    let verifier =
                        rustls_platform_verifier::Verifier::new(Arc::new(crypto_provider))
                            .expect("can create verifier");

                    Box::new(TokioBlockingThreadVerifier::new(verifier))
                });
                return set_up_platform_verifier(connector, host, &**verifier);
            }
            RootCertificates::FromStaticDers(ders) => ders,
            RootCertificates::FromDer(der) => &[der],
        };
        let mut store_builder = X509StoreBuilder::new()?;
        for der in ders {
            store_builder.add_cert(X509::from_der(der)?.as_ref())?;
        }
        connector.set_verify_cert_store(store_builder.build())?;
        Ok(())
    }
}

impl std::fmt::Debug for RootCertificates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native => write!(f, "Native"),
            Self::FromStaticDers(ders) => f
                .debug_tuple("FromStaticDers")
                .field(&format_args!("<{} cert(s)>", ders.len()))
                .finish(),
            Self::FromDer(_) => f.debug_tuple("FromDer").field(&"_").finish(),
        }
    }
}

#[derive(Debug)]
struct UnimplementedRustlsSecureRandom;
impl rustls::crypto::SecureRandom for UnimplementedRustlsSecureRandom {
    fn fill(&self, _buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        unimplemented!(
            "should not need cryptography for rustls-platform-verifier to only verify TLS certs"
        );
    }
}
#[derive(Debug)]
struct UnimplementedRustlsKeyProvider;
impl rustls::crypto::KeyProvider for UnimplementedRustlsKeyProvider {
    fn load_private_key(
        &self,
        _key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        unimplemented!(
            "should not need cryptography for rustls-platform-verifier to only verify TLS certs"
        );
    }
}

/// A subset of [`ServerCertVerifier`] that only exposes
/// [`verify_server_cert`](ServerCertVerifier::verify_server_cert) as an async function.
trait LimitedServerCertVerifier: Send + Sync {
    fn verify_server_cert(
        &self,
        end_entity: CertificateDer<'static>,
        intermediates: Vec<CertificateDer<'static>>,
        server_name: &Arc<ServerName<'static>>,
    ) -> BoxFuture<'static, Result<ServerCertVerified, rustls::Error>>;
}

impl LimitedServerCertVerifier for &dyn LimitedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: CertificateDer<'static>,
        intermediates: Vec<CertificateDer<'static>>,
        server_name: &Arc<ServerName<'static>>,
    ) -> BoxFuture<'static, Result<ServerCertVerified, rustls::Error>> {
        (**self).verify_server_cert(end_entity, intermediates, server_name)
    }
}

/// Configures [rustls_platform_verifier] as a BoringSSL (async) custom verify callback.
///
/// We make it async because the platform verification can do unbounded work (on Android we have
/// observed it doing network activity!)
///
/// Note that `connector` will **depend on tokio** to verify certificates. Moreover, when using the
/// resulting [`boring_signal::ssl::Ssl`] object, you must call `set_task_waker`. This will be taken
/// care of for you if you use tokio-boring (and always poll within a tokio context).
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

    // We're going to share this across each of the verifier tasks.
    let host_as_server_name = Arc::new(host_as_server_name);

    // For maximum generality, this is a *function* that returns a *future* that returns a
    // *function.* We do as much checking up front as we can before spawning the
    // potentially-blocking work, but then after that we just return the result directly.
    connector.set_async_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        // Get the certificate chain and reject compromised CA keys before handing it to the
        // platform verifier. Most platform-verifier backends don't use rustls-webpki for path
        // validation, so rustls-webpki's built-in distrust list does not protect them.
        let cert_chain = ssl.peer_cert_chain().ok_or(SslAlert::NO_CERTIFICATE)?;
        for cert in cert_chain {
            match uses_distrusted_emudhra_key(cert) {
                Ok(false) => {}
                Ok(true) => {
                    log::warn!("TLS certificate chain uses a distrusted eMudhra CA key");
                    return Err(SslAlert::CERTIFICATE_REVOKED);
                }
                Err(_) => return Err(SslAlert::BAD_CERTIFICATE),
            }
        }

        // Lazily convert each certificate to DER (as expected by rustls).
        let mut cert_chain = cert_chain.into_iter().map(|cert| Ok(cert.to_der()?.into()));

        // The head of the chain should be the leaf certificate.
        let end_entity = match cert_chain.next() {
            Some(Ok(leaf_cert)) => leaf_cert,
            None | Some(Err(_)) => {
                return Err(SslAlert::BAD_CERTIFICATE);
            }
        };

        // The rest of the chain should be valid intermediate certificates.
        let intermediates: Vec<CertificateDer<'static>> = cert_chain
            .collect::<Result<_, boring_signal::error::ErrorStack>>()
            .map_err(|_| SslAlert::BAD_CERTIFICATE)?;

        let task = verifier.verify_server_cert(end_entity, intermediates, &host_as_server_name);
        let host_for_logging = host_as_server_name.clone();

        Ok(Box::pin(async move {
            task.await.map_err(move |e| {
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
                    log_safe_domain(&host_for_logging.to_str()),
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
                        rustls::CertificateError::NotValidForName => SslAlert::CERTIFICATE_UNKNOWN,
                        rustls::CertificateError::InvalidPurpose => SslAlert::CERTIFICATE_UNKNOWN,
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

/// [`LimitedServerCertVerifier`] that runs verification by spawning onto the current tokio blocking
/// thread pool.
struct TokioBlockingThreadVerifier<T> {
    verifier: Arc<T>,
}

impl<T: ServerCertVerifier + 'static> TokioBlockingThreadVerifier<T> {
    fn new(verifier: T) -> Self {
        Self {
            verifier: Arc::new(verifier),
        }
    }
}

impl<T: ServerCertVerifier + 'static> LimitedServerCertVerifier for TokioBlockingThreadVerifier<T> {
    fn verify_server_cert(
        &self,
        end_entity: CertificateDer<'static>,
        intermediates: Vec<CertificateDer<'static>>,
        server_name: &Arc<ServerName<'static>>,
    ) -> BoxFuture<'static, Result<ServerCertVerified, rustls::Error>> {
        let verifier = self.verifier.clone();
        let server_name = server_name.clone();
        Box::pin(async move {
            let task = tokio::task::spawn_blocking(move || {
                // We don't do our own OCSP. Either the platform will do its own checks, or it won't.
                let ocsp_response = [];
                verifier.verify_server_cert(
                    &end_entity,
                    &intermediates,
                    &server_name,
                    &ocsp_response,
                    rustls::pki_types::UnixTime::now(),
                )
            });
            task.await.unwrap_or_else(|_panic: tokio::task::JoinError| {
                Err(rustls::CertificateError::ApplicationVerificationFailure.into())
            })
        })
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, LazyLock};

    use assert_matches::assert_matches;
    use boring_signal::pkey::Private;
    use boring_signal::ssl::{ErrorCode, SslAcceptor, SslConnector, SslMethod};
    use boring_signal::x509::X509VerifyError;
    use rcgen::{CertificateParams, DnType, Issuer, KeyPair};
    use rustls::RootCertStore;
    use tokio::net::TcpStream;

    use super::*;
    use crate::tcp_ssl::proxy::testutil::PROXY_CERTIFICATE;
    use crate::tcp_ssl::testutil::{
        SERVER_CERTIFICATE, SERVER_HOSTNAME, make_http_request_response_over,
        simple_localhost_https_server,
    };

    struct AllowSync<T>(T);
    struct AllowAll(Arc<AtomicBool>);

    /// The private key for EMDVTLSCAG3B, one of the keys blocked by rustls-webpki 0.103.16.
    ///
    /// The private scalar for this compromised public key is intentionally public knowledge.
    static COMPROMISED_SIGNING_KEY: LazyLock<KeyPair> = LazyLock::new(|| {
        KeyPair::from_pem(
            "-----BEGIN PRIVATE KEY-----\n\
             MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAAAAAAAAAAAAAAAAAA\n\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJyhZANiAATnntnASpdz\n\
             xHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BOL4vJf3SFumWqkR7o\n\
             pORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKTXSnUT5HhVga2PM7atGg=\n\
             -----END PRIVATE KEY-----",
        )
        .expect("valid key")
    });

    const COMPROMISED_ISSUER_NAME: &str = "EM DV TLS CA - G3B";

    fn certificate_params(common_name: &str) -> CertificateParams {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params
    }

    fn make_certificate(
        subject_key: &KeyPair,
        subject_common_name: &str,
        issuer_key: &KeyPair,
        issuer_common_name: &str,
    ) -> X509 {
        let issuer = Issuer::new(certificate_params(issuer_common_name), issuer_key);
        let cert = certificate_params(subject_common_name)
            .signed_by(subject_key, &issuer)
            .expect("can sign");
        X509::from_der(cert.der()).expect("valid certificate")
    }

    fn certificate_signed_by_compromised_key() -> (PKey<Private>, X509) {
        let leaf_key = KeyPair::generate().expect("can generate key");
        let cert = make_certificate(
            &leaf_key,
            SERVER_HOSTNAME,
            &COMPROMISED_SIGNING_KEY,
            COMPROMISED_ISSUER_NAME,
        );
        let leaf_key =
            PKey::private_key_from_der(leaf_key.serialized_der()).expect("valid leaf key");
        (leaf_key, cert)
    }

    #[test]
    fn distrusted_emudhra_spkis_match_hashes() {
        assert_eq!(
            DISTRUSTED_EMUDHRA_SPKIS.len(),
            DISTRUSTED_EMUDHRA_SPKI_SHA256.len()
        );
        for (spki, expected_digest) in DISTRUSTED_EMUDHRA_SPKIS
            .iter()
            .zip(DISTRUSTED_EMUDHRA_SPKI_SHA256)
        {
            assert_eq!(
                hash(MessageDigest::sha256(), spki)
                    .expect("can hash SPKI")
                    .as_ref(),
                expected_digest
            );
        }
    }

    #[test]
    fn recognizes_certificate_signed_by_distrusted_emudhra_key() {
        let (_, cert) = certificate_signed_by_compromised_key();

        assert!(uses_distrusted_emudhra_key(&cert).expect("can inspect certificate"));

        let compromised_cert = make_certificate(
            &COMPROMISED_SIGNING_KEY,
            COMPROMISED_ISSUER_NAME,
            &COMPROMISED_SIGNING_KEY,
            COMPROMISED_ISSUER_NAME,
        );
        assert!(uses_distrusted_emudhra_key(&compromised_cert).expect("can inspect certificate"));

        let safe_key = &SERVER_CERTIFICATE.signing_key;
        let safe_cert_with_matching_issuer_name =
            make_certificate(safe_key, SERVER_HOSTNAME, safe_key, COMPROMISED_ISSUER_NAME);
        assert!(
            !uses_distrusted_emudhra_key(&safe_cert_with_matching_issuer_name)
                .expect("can inspect certificate")
        );

        assert!(
            !uses_distrusted_emudhra_key(
                &X509::from_der(SERVER_CERTIFICATE.cert.der()).expect("valid certificate")
            )
            .expect("can inspect certificate")
        );
    }

    #[test]
    fn x509_verify_mismatch_leaves_errors_in_boringssl_error_queue() {
        // This pins down the BoringSSL behavior that uses_distrusted_emudhra_key has to work
        // around. If the first half of this test starts failing, the drain in that function is no
        // longer needed. If the drain is removed while the first half still passes, every handshake
        // that goes through set_up_platform_verifier fails (see verify_certificate_via_rustls),
        // because SSL_get_error reports the stale entries instead of WANT_READ /
        // WANT_CERTIFICATE_VERIFY.
        let safe_cert = X509::from_der(SERVER_CERTIFICATE.cert.der()).expect("valid certificate");

        // Start from a clean queue so we only observe what X509_verify leaves behind.
        drop(ErrorStack::get());
        assert!(
            !safe_cert
                .verify(&DISTRUSTED_EMUDHRA_KEYS[0])
                .expect("can verify")
        );
        assert!(!ErrorStack::get().errors().is_empty());

        assert!(!uses_distrusted_emudhra_key(&safe_cert).expect("can inspect certificate"));
        assert!(ErrorStack::get().errors().is_empty());
    }

    impl LimitedServerCertVerifier for AllowAll {
        fn verify_server_cert(
            &self,
            _end_entity: CertificateDer<'static>,
            _intermediates: Vec<CertificateDer<'static>>,
            _server_name: &Arc<ServerName<'static>>,
        ) -> BoxFuture<'static, Result<ServerCertVerified, rustls::Error>> {
            self.0.store(true, Ordering::Relaxed);
            Box::pin(std::future::ready(Ok(ServerCertVerified::assertion())))
        }
    }

    #[tokio::test]
    async fn rejects_certificate_signed_by_omitted_distrusted_intermediate() {
        let (leaf_key, leaf_cert) = certificate_signed_by_compromised_key();
        let listener =
            std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("can bind to localhost");
        listener
            .set_nonblocking(true)
            .expect("can make nonblocking");
        let addr = listener.local_addr().expect("has local address");
        let server = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("valid listener");
            let (transport, _) = listener.accept().await.expect("can accept");
            let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).expect("can build");
            acceptor.set_private_key(&leaf_key).expect("valid key");
            acceptor
                .set_certificate(&leaf_cert)
                .expect("valid certificate");
            let _ = tokio_boring_signal::accept(&acceptor.build(), transport).await;
        });

        let mut connector = SslConnector::builder(SslMethod::tls()).expect("can build");
        let platform_verifier_called = Arc::new(AtomicBool::new(false));
        set_up_platform_verifier(
            &mut connector,
            Host::Domain(SERVER_HOSTNAME),
            AllowAll(platform_verifier_called.clone()),
        )
        .expect("valid verifier configuration");
        let transport = TcpStream::connect(addr).await.expect("can connect");
        let error = tokio_boring_signal::connect(
            connector.build().configure().expect("valid connector"),
            SERVER_HOSTNAME,
            transport,
        )
        .await
        .expect_err("compromised issuer must be rejected before platform verification");
        assert_eq!(error.code(), Some(ErrorCode::SSL));
        assert!(!platform_verifier_called.load(Ordering::Relaxed));
        server.await.expect("server task completed");
    }

    impl<T: ServerCertVerifier + 'static> LimitedServerCertVerifier for AllowSync<T> {
        fn verify_server_cert(
            &self,
            end_entity: CertificateDer<'static>,
            intermediates: Vec<CertificateDer<'static>>,
            server_name: &Arc<ServerName<'static>>,
        ) -> BoxFuture<'static, Result<ServerCertVerified, rustls::Error>> {
            // We don't do our own OCSP. Either the platform will do its own checks, or it won't.
            let ocsp_response = [];
            Box::pin(std::future::ready(self.0.verify_server_cert(
                &end_entity,
                &intermediates,
                server_name,
                &ocsp_response,
                rustls::pki_types::UnixTime::now(),
            )))
        }
    }

    #[test_case::test_case(AllowSync)]
    #[test_case::test_case(TokioBlockingThreadVerifier::new)]
    #[tokio::test]
    async fn verify_certificate_via_rustls<V: LimitedServerCertVerifier + 'static>(
        make_verifier: fn(rustls::client::WebPkiServerVerifier) -> V,
    ) {
        let (addr, server) = simple_localhost_https_server();
        let _server_handle = tokio::spawn(server);

        let mut root_cert_store = RootCertStore::empty();
        root_cert_store
            .add(SERVER_CERTIFICATE.cert.der().clone())
            .expect("valid");
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_cert_store))
            .build()
            .expect("valid");

        let mut ssl = SslConnector::builder(SslMethod::tls()).expect("valid");
        let verifier = Arc::into_inner(verifier).expect("only one referent");
        let verifier = make_verifier(verifier);
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

    #[test_case::test_case(AllowSync)]
    #[test_case::test_case(TokioBlockingThreadVerifier::new)]
    #[tokio::test]
    async fn verify_certificate_failure_via_rustls<V: LimitedServerCertVerifier + 'static>(
        make_verifier: fn(rustls::client::WebPkiServerVerifier) -> V,
    ) {
        let (addr, server) = simple_localhost_https_server();
        let _server_handle = tokio::spawn(server);

        let mut root_cert_store = RootCertStore::empty();
        // Wrong certificate here!
        root_cert_store
            .add(PROXY_CERTIFICATE.cert.der().clone())
            .expect("valid");
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_cert_store))
            .build()
            .expect("valid");

        let mut ssl = SslConnector::builder(SslMethod::tls()).expect("valid");
        let verifier = Arc::into_inner(verifier).expect("only one referent");
        let verifier = make_verifier(verifier);
        set_up_platform_verifier(&mut ssl, Host::Domain(SERVER_HOSTNAME), verifier).expect("valid");

        let transport = TcpStream::connect(addr).await.expect("can connect");
        let err = assert_matches!(
            tokio_boring_signal::connect(
                ssl.build().configure().expect("valid"),
                SERVER_HOSTNAME,
                transport,
            )
            .await,
            Err(e) if e.code() == Some(ErrorCode::SSL) => e
        );
        let failure = err.ssl().and_then(|ssl| ssl.verify_result().err());
        assert_matches!(failure, Some(X509VerifyError::APPLICATION_VERIFICATION));
    }
}
