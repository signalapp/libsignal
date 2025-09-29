//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::future::Future;
use std::ops::ControlFlow;
use std::sync::Arc;

use crate::chat::noise::encrypted_stream::{ChatNoiseConnector, EncryptedStream};
use crate::chat::noise::{Authorization, ChatNoiseRoute, ConnectError, ConnectMeta};
use crate::infra::errors::{LogSafeDisplay, TransportConnectError};
use crate::infra::noise::{NoiseConnector, NoiseDirectConnector, SendError, Transport};
use crate::infra::route::{ComposedConnector, NoDelay, TcpRoute, UnresolvedHost};
use crate::infra::tcp_ssl::StatelessTcp;
use crate::infra::{AsHttpHeader as _, Connection};

pub struct NoiseDirectConnectShadow<'a> {
    pub route_resolver: libsignal_net_infra::route::RouteResolver,
    pub dns_resolver: libsignal_net_infra::dns::DnsResolver,
    pub noise_config: crate::env::NoiseConnectionConfig,
    pub language_list: crate::chat::LanguageList,
    pub user_agent: &'a crate::env::UserAgent,
}

#[derive(Debug, derive_more::From, displaydoc::Display)]
#[expect(dead_code)]
enum Error {
    /// IO: {0}
    Io(#[from] std::io::ErrorKind),
    /// connect failed: {0}
    Fatal(#[from] Fatal),
}
impl LogSafeDisplay for Error where Fatal: LogSafeDisplay {}

#[derive(Debug, displaydoc::Display)]
/// {log_safe}
struct Fatal {
    log_safe: Cow<'static, str>,
}
impl LogSafeDisplay for Fatal {}

impl Fatal {
    fn log_safe(s: impl Into<Cow<'static, str>>) -> Self {
        Fatal { log_safe: s.into() }
    }
}

impl NoiseDirectConnectShadow<'_> {
    pub fn connect(
        self,
    ) -> impl Future<
        Output = Result<
            EncryptedStream<impl Transport + Connection>,
            libsignal_net_infra::route::ConnectError<impl LogSafeDisplay>,
        >,
    > + 'static {
        let Self {
            route_resolver,
            dns_resolver,
            noise_config,
            language_list,
            user_agent,
        } = self;

        let meta = ConnectMeta {
            accept_language: language_list
                .into_header()
                .map(|(_name, value)| value.to_str().expect("valid string").to_owned())
                .unwrap_or_default(),
            user_agent: user_agent
                .as_header()
                .1
                .to_str()
                .expect("valid string")
                .to_owned(),
        };

        let crate::env::NoiseConnectionConfig {
            hostname,
            port,
            server_public_key,
        } = noise_config;

        let noise_route = ChatNoiseRoute {
            fragment: (
                Authorization::Anonymous {
                    server_public_key: *server_public_key,
                },
                meta,
            ),
            inner: TcpRoute {
                address: UnresolvedHost::from(Arc::from(hostname)),
                port,
            },
        };

        async move {
            let result = crate::infra::route::connect(
                &route_resolver,
                NoDelay,
                std::iter::once(noise_route),
                &dns_resolver,
                ComposedConnector::<_, _, ConnectError>::new(
                    ChatNoiseConnector(NoiseConnector),
                    NoiseDirectConnector(StatelessTcp),
                ),
                (),
                "noise shadow",
                |e| match e {
                    ConnectError::Send(e) => match e {
                        SendError::Io(e) => {
                            log::info!("Noise Direct connection failed: {}", e.kind());
                            ControlFlow::Continue(())
                        }

                        SendError::Noise(error) => ControlFlow::Break(Fatal {
                            log_safe: format!("noise error: {error}").into(),
                        }),
                    },
                    ConnectError::Transport(e) => match e {
                        TransportConnectError::InvalidConfiguration => ControlFlow::Break(
                            Fatal::log_safe("invalid configuration (this should never happen)"),
                        ),
                        TransportConnectError::ClientAbort => {
                            ControlFlow::Break(Fatal::log_safe("connect aborted"))
                        }
                        TransportConnectError::TcpConnectionFailed
                        | TransportConnectError::SslError(_)
                        | TransportConnectError::CertError
                        | TransportConnectError::SslFailedHandshake(_)
                        | TransportConnectError::ProxyProtocol => ControlFlow::Continue(()),
                    },
                    ConnectError::WrongPublicKey
                    | ConnectError::ClientVersionTooOld
                    | ConnectError::InvalidResponseCode(_)
                    | ConnectError::ProtobufDecode
                    | ConnectError::UnexpectedFastOpenResponse => {
                        ControlFlow::Break(Fatal::log_safe(format!("server rejected: {e}")))
                    }
                },
            )
            .await;
            // The outcome updates don't matter since we're using a NoDelay policy.
            let (result, _outcomes) = result;

            result
        }
    }
}
