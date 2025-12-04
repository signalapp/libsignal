//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use auto_enums::enum_derive;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_socks::TargetAddr;
use tokio_socks::tcp::{Socks4Stream, Socks5Stream};

use crate::Connection;
use crate::dns::DnsResolver;
use crate::errors::TransportConnectError;
use crate::host::Host;
use crate::route::{Connector, ConnectorExt as _, SocksRoute, TcpRoute};
use crate::tcp_ssl::TcpStream;

pub(crate) const LONG_FULL_CONNECT_THRESHOLD: Duration = super::LONG_TCP_HANDSHAKE_THRESHOLD
    .saturating_add(super::LONG_TLS_HANDSHAKE_THRESHOLD)
    .saturating_add(Duration::from_secs(3));

#[derive(Clone)]
pub struct SocksConnector {
    pub proxy_host: Host<Arc<str>>,
    pub proxy_port: NonZeroU16,
    pub protocol: Protocol,
    pub resolve_hostname_locally: bool,
    /// The DNS resolver to use to locate the proxy, and, if
    /// `resolve_hostname_locally` is set, the IP address of the remote host.
    pub dns_resolver: DnsResolver,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, strum::EnumDiscriminants)]
#[strum_discriminants(name(ProtocolKind))]
pub enum Protocol {
    Socks4 {
        user_id: Option<String>,
    },
    Socks5 {
        username_password: Option<(String, String)>,
    },
}

#[derive(Debug, derive_more::From)]
#[enum_derive(tokio1::AsyncRead, tokio1::AsyncWrite)]
pub enum SocksStream<S> {
    Socks4(Socks4Stream<S>),
    Socks5(Socks5Stream<S>),
}

impl Connector<SocksRoute<IpAddr>, ()> for super::StatelessProxied {
    type Connection = SocksStream<TcpStream>;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        (): (),
        route: SocksRoute<IpAddr>,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let SocksRoute {
            protocol,
            proxy,
            target_addr,
            target_port,
        } = route;

        async move {
            log::info!("[{log_tag}] establishing connection to host over SOCKS proxy");
            log::debug!("[{log_tag}] establishing connection to {target_addr:?} over SOCKS proxy");

            log::info!("[{log_tag}] connecting to {protocol:?} proxy over TCP");
            let TcpRoute {
                address: proxy_host,
                port: proxy_port,
                ..
            } = &proxy;
            log::debug!(
                "[{log_tag}] connecting to {protocol:?} proxy at {proxy_host}:{proxy_port} over TCP"
            );

            let target = match &target_addr {
                crate::route::ProxyTarget::ResolvedLocally(ip) => {
                    TargetAddr::Ip((*ip, target_port.get()).into())
                }
                crate::route::ProxyTarget::ResolvedRemotely { name } => {
                    TargetAddr::Domain(Cow::Borrowed(name), target_port.get())
                }
            };

            let stream = super::super::StatelessTcp.connect(proxy, log_tag).await?;
            log::info!("[{log_tag}] performing proxy handshake");
            log::debug!("[{log_tag}] performing proxy handshake with {target:?}");
            protocol
                .connect_to_proxy(stream, target)
                .await
                .map_err(|_: tokio_socks::Error| TransportConnectError::ProxyProtocol)
        }
    }
}

impl Connection for Socks4Stream<TcpStream> {
    fn transport_info(&self) -> crate::TransportInfo {
        (**self).transport_info()
    }
}

impl Connection for Socks5Stream<TcpStream> {
    fn transport_info(&self) -> crate::TransportInfo {
        (**self).transport_info()
    }
}

impl Connection for SocksStream<TcpStream> {
    fn transport_info(&self) -> crate::TransportInfo {
        match self {
            SocksStream::Socks4(stream) => stream.transport_info(),
            SocksStream::Socks5(stream) => stream.transport_info(),
        }
    }
}

impl Protocol {
    async fn connect_to_proxy<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        target: TargetAddr<'_>,
    ) -> Result<SocksStream<S>, tokio_socks::Error> {
        match self {
            Protocol::Socks5 { username_password } => match username_password {
                Some((username, password)) => {
                    Socks5Stream::connect_with_password_and_socket(
                        stream, target, username, password,
                    )
                    .await
                }
                None => Socks5Stream::connect_with_socket(stream, target).await,
            }
            .map(Into::into),
            Protocol::Socks4 { user_id } => match user_id {
                Some(user_id) => {
                    Socks4Stream::connect_with_userid_and_socket(stream, target, user_id).await
                }
                None => Socks4Stream::connect_with_socket(stream, target).await,
            }
            .map(Into::into),
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use futures_util::{FutureExt as _, select};
    use test_case::test_matrix;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::join;

    use super::*;
    use crate::OverrideNagleAlgorithm;
    use crate::route::ProxyTarget;
    use crate::tcp_ssl::proxy::StatelessProxied;
    use crate::tcp_ssl::proxy::testutil::{TcpServer, TlsServer};
    use crate::tcp_ssl::testutil::{SERVER_CERTIFICATE, SERVER_HOSTNAME};

    /// Authentication method.
    #[derive(Default)]
    struct Authentication {
        expect_password: bool,
        deny_all: bool,
    }

    #[derive(Debug, PartialEq)]
    struct AuthOutput {
        provided_username_password: Option<(String, String)>,
        accepted: bool,
    }

    type AuthResult = Result<AuthOutput, socks5_server::proto::handshake::password::Error>;

    #[async_trait]
    impl socks5_server::Auth for Authentication {
        type Output = AuthResult;

        fn as_handshake_method(&self) -> socks5_server::proto::handshake::Method {
            if self.expect_password {
                socks5_server::proto::handshake::Method::PASSWORD
            } else {
                socks5_server::proto::handshake::Method::NONE
            }
        }
        async fn execute(&self, stream: &mut tokio::net::TcpStream) -> Self::Output {
            log::debug!("authenticating incoming stream");
            let accept = !self.deny_all;

            log::debug!("will accept: {accept}");
            let provided_username_password = if self.expect_password {
                let request =
                    socks5_server::proto::handshake::password::Request::read_from(stream).await?;
                socks5_server::proto::handshake::password::Response::new(accept)
                    .write_to(stream)
                    .await?;
                log::debug!("saving credentials");
                Some((
                    String::from_utf8(request.username).unwrap(),
                    String::from_utf8(request.password).unwrap(),
                ))
            } else {
                if accept {
                    log::debug!("allowing unauthenticated connection");
                } else {
                    log::debug!("rejecting unauthenticated connection");
                    socks5_server::proto::handshake::Response::new(
                        socks5_server::proto::handshake::Method::UNACCEPTABLE,
                    )
                    .write_to(stream)
                    .await?;
                }
                None
            };
            stream.flush().await.expect("can flush");

            Ok(AuthOutput {
                provided_username_password,
                accepted: accept,
            })
        }
    }

    struct Socks5Server(socks5_server::Server<AuthResult>);

    impl Socks5Server {
        fn new(auth: Arc<Authentication>) -> Self {
            let tcp_server = TcpServer::bind_localhost();
            let server = socks5_server::Server::new(tcp_server.into_listener(), auth as Arc<_>);
            Self(server)
        }
        async fn accept(
            &self,
        ) -> socks5_server::connection::IncomingConnection<
            AuthResult,
            socks5_server::connection::state::NeedAuthenticate,
        > {
            let (incoming, _client_addr) = self.0.accept().await.expect("valid handshake");
            incoming
        }
    }

    const VALID_CREDS: (&str, &str) = ("abc", "password");

    #[derive(Copy, Clone)]
    enum Auth {
        Authenticated,
        Unauthenticated,
    }
    #[derive(Copy, Clone)]
    enum TargetAddressType {
        HostnameTarget,
        IpTarget,
    }

    use Auth::*;
    use TargetAddressType::*;

    #[test_matrix(
        (Authenticated, Unauthenticated),
        (IpTarget, HostnameTarget)
    )]
    #[tokio::test]
    async fn socks5_server_basic_e2e(auth: Auth, target_addr: TargetAddressType) {
        let proxy_credentials = match auth {
            Authenticated => Some((VALID_CREDS.0.to_owned(), VALID_CREDS.1.to_owned())),
            Unauthenticated => None,
        };
        let expect_password = proxy_credentials.is_some();

        let _ = env_logger::try_init();
        let proxy = Socks5Server::new(
            Authentication {
                expect_password,
                deny_all: false,
            }
            .into(),
        );

        let tcp_server = TcpServer::bind_localhost();
        let target_host = match target_addr {
            HostnameTarget => ProxyTarget::ResolvedRemotely {
                name: SERVER_HOSTNAME.into(),
            },
            IpTarget => ProxyTarget::ResolvedLocally(tcp_server.listen_addr.ip()),
        };
        let expected_client_target_addr = match target_addr {
            HostnameTarget => socks5_server::proto::Address::DomainAddress(
                SERVER_HOSTNAME.into(),
                tcp_server.listen_addr.port(),
            ),
            IpTarget => socks5_server::proto::Address::SocketAddress(tcp_server.listen_addr),
        };
        let proxy_addr = {
            let local_addr = proxy.0.local_addr().unwrap();
            TcpRoute {
                address: local_addr.ip(),
                port: local_addr.port().try_into().unwrap(),
                override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
            }
        };

        let mut connect = std::pin::pin!(StatelessProxied.connect(
            SocksRoute {
                proxy: proxy_addr,
                target_addr: target_host,
                target_port: tcp_server.listen_addr.port().try_into().unwrap(),
                protocol: Protocol::Socks5 {
                    username_password: proxy_credentials.clone(),
                },
            },
            "socks test",
        ));

        // Use `select!` to drive both futures since they both need to make
        // progress: the client needs to start connecting, and the proxy needs
        // to accept the incoming TCP connection.
        let proxy_server_connection = select! {
            connection = proxy.accept().fuse() => connection,
            _ = connect.as_mut().fuse() => unreachable!("client can't finish connection until the server accepts"),
        };

        // Start a task to handle the proxying. The proxy will connect
        // internally to the TCP server, then proxy until one or the other end
        // of the connection is closed.
        let proxy_task = tokio::spawn(async move {
            let (after_auth, auth_outcome) = proxy_server_connection
                .authenticate()
                .await
                .expect("client implements protocol correctly");
            let command = after_auth.wait().await.expect("client sends command");
            let (connect, address) = assert_matches!(command, socks5_server::Command::Connect(connect, address) => (connect, address));
            let mut connection = connect
                .reply(
                    socks5_server::proto::Reply::Succeeded,
                    socks5_server::proto::Address::SocketAddress(tcp_server.listen_addr),
                )
                .await
                .expect("can reply");

            let mut proxy_to_server = tokio::net::TcpStream::connect(tcp_server.listen_addr)
                .await
                .expect("can connect to TCP server");

            tokio::io::copy_bidirectional(&mut connection, &mut proxy_to_server)
                .await
                .expect("ends gracefully");

            (auth_outcome, address)
        });

        let ((mut server_connection, _server_addr), mut client_connection) = join!(
            tcp_server.accept(),
            connect.map(|r| r.expect("connected successfully"))
        );

        // If we send on the client connection, it should get received on the server connection.
        const SENT_MESSAGE: &[u8] = b"hello there";
        let mut server_buf = [0; SENT_MESSAGE.len()];

        let ((), ()) = join!(
            client_connection
                .write_all(SENT_MESSAGE)
                .map(|r| r.expect("can write")),
            server_connection
                .read_exact(&mut server_buf)
                .map(|r| assert_eq!(r.expect("can read all"), SENT_MESSAGE.len()))
        );
        assert_eq!(server_buf, SENT_MESSAGE);

        // Drop the client and server connections so they get closed and the
        // proxy can finish. Then we can assert on the values received by the
        // proxy from the client.
        drop(server_connection);
        drop(client_connection);

        let (auth_from_client, client_target_addr) =
            proxy_task.await.expect("finishes successfully");
        assert_eq!(client_target_addr, expected_client_target_addr);
        assert_eq!(
            auth_from_client.expect("handshake succeeded"),
            AuthOutput {
                provided_username_password: proxy_credentials,
                accepted: true,
            }
        );
    }

    #[tokio::test]
    async fn server_rejects_authentication() {
        let proxy = Socks5Server::new(
            Authentication {
                deny_all: true,
                expect_password: true,
            }
            .into(),
        );

        let tls_server = TlsServer::new(TcpServer::bind_localhost(), &SERVER_CERTIFICATE);

        let proxy_credentials = ("abc".to_owned(), "password".to_owned());
        let proxy_addr = {
            let local_addr = proxy.0.local_addr().unwrap();
            TcpRoute {
                address: local_addr.ip(),
                port: local_addr.port().try_into().unwrap(),
                override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
            }
        };

        let connect = std::pin::pin!(StatelessProxied.connect(
            SocksRoute {
                proxy: proxy_addr,
                target_addr: ProxyTarget::ResolvedRemotely {
                    name: SERVER_HOSTNAME.into()
                },
                target_port: tls_server.tcp.listen_addr.port().try_into().unwrap(),
                protocol: Protocol::Socks5 {
                    username_password: Some(proxy_credentials.clone()),
                },
            },
            "socks test",
        ));

        let proxy_accept_and_negotiate = async {
            let (_connection, auth_outcome) = proxy
                .accept()
                .await
                .authenticate()
                .await
                .expect("client sent auth");
            auth_outcome.expect("wrote response to client")
        };

        let (proxy_server_auth_outcome, client_result) =
            join!(proxy_accept_and_negotiate.fuse(), connect.fuse());

        // Double-check that the server rejected the request.
        assert_eq!(
            proxy_server_auth_outcome,
            AuthOutput {
                provided_username_password: Some(proxy_credentials),
                accepted: false,
            }
        );

        // The client should see the rejection as well.
        assert_matches!(client_result, Err(TransportConnectError::ProxyProtocol));
    }
}
