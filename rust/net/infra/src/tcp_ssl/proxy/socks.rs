//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::fmt::Display;
use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use auto_enums::enum_derive;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_boring_signal::SslStream;
use tokio_socks::tcp::{Socks4Stream, Socks5Stream};
use tokio_socks::TargetAddr;

use crate::dns::lookup_result::LookupResult;
use crate::dns::DnsResolver;
use crate::errors::TransportConnectError;
use crate::host::Host;
use crate::route::{Connector, ConnectorExt as _, SocksRoute, TcpRoute};
use crate::{
    Alpn, Connection, DnsSource, RouteType, ServiceConnectionInfo, StreamAndInfo,
    TransportConnectionParams, TransportConnector,
};

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

#[async_trait]
impl TransportConnector for SocksConnector {
    type Stream = SslStream<SocksStream<TcpStream>>;

    async fn connect(
        &self,
        connection_params: &TransportConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let Self {
            resolve_hostname_locally,
            protocol,
            proxy_host,
            proxy_port,
            dns_resolver,
        } = self;

        log::info!("establishing connection to host over SOCKS proxy");
        log::debug!(
            "establishing connection to {} over SOCKS proxy",
            connection_params.tcp_host
        );

        let which_protocol = ProtocolKind::from(protocol);
        log::info!("connecting to {which_protocol:?} proxy over TCP");
        log::debug!("connecting to {which_protocol:?} proxy at {proxy_host}:{proxy_port} over TCP");

        let log_tag: Arc<str> = "SocksConnector".into();

        let StreamAndInfo(tcp_stream, remote_address) = crate::tcp_ssl::connect_tcp(
            dns_resolver,
            RouteType::SocksProxy,
            proxy_host.as_deref(),
            *proxy_port,
            log_tag.clone(),
        )
        .await?;
        let is_ipv6 = tcp_stream
            .peer_addr()
            .expect("can retrieve addr info")
            .is_ipv6();

        let (target, dns_source) = match &connection_params.tcp_host {
            Host::Ip(ip) => (
                TargetAddr::Ip((*ip, connection_params.port.get()).into()),
                DnsSource::Static,
            ),
            Host::Domain(host) if *resolve_hostname_locally => {
                let LookupResult { source, ipv4, ipv6 } = dns_resolver
                    .lookup_ip(host)
                    .await
                    .map_err(|_| TransportConnectError::DnsError)?;
                let ipv4 = ipv4.into_iter().map(IpAddr::from);
                let ipv6 = ipv6.into_iter().map(IpAddr::from);

                // Prefer the same address family as is being used to connect to the proxy.
                let address = if is_ipv6 {
                    ipv6.chain(ipv4).next()
                } else {
                    ipv4.chain(ipv6).next()
                }
                .ok_or(TransportConnectError::DnsError)?;
                (
                    TargetAddr::Ip((address, connection_params.port.get()).into()),
                    source,
                )
            }
            Host::Domain(host) => (
                TargetAddr::Domain(Cow::Borrowed(host), connection_params.port.get()),
                DnsSource::Delegated,
            ),
        };

        log::info!("performing proxy handshake");
        log::debug!("performing proxy handshake with {target:?}");

        let socks_stream = protocol
            .connect_to_proxy(tcp_stream, target)
            .await
            .map_err(|e| {
                let e = ErrorForLog(e);
                log::warn!("proxy connection failed: {e}");
                TransportConnectError::ProxyProtocol
            })?;

        log::debug!("connecting TLS through proxy");
        let stream =
            crate::tcp_ssl::connect_tls(socks_stream, connection_params, alpn, log_tag).await?;

        log::info!("connection through SOCKS proxy established successfully");
        Ok(StreamAndInfo(
            stream,
            ServiceConnectionInfo {
                route_type: RouteType::SocksProxy,
                dns_source,
                address: remote_address.address,
            },
        ))
    }
}

impl Connector<SocksRoute<IpAddr>, ()> for super::StatelessProxied {
    type Connection = SocksStream<TcpStream>;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        (): (),
        route: SocksRoute<IpAddr>,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let SocksRoute {
            protocol,
            proxy,
            target_addr,
            target_port,
        } = route;

        async move {
            log::info!("[{log_tag}] establishing connection to host over SOCKS proxy");
            log::debug!(
                "[{log_tag}] establishing connection to {:?} over SOCKS proxy",
                target_addr
            );

            log::info!("[{log_tag}] connecting to {protocol:?} proxy over TCP");
            let TcpRoute {
                address: proxy_host,
                port: proxy_port,
            } = &proxy;
            log::debug!("[{log_tag}] connecting to {protocol:?} proxy at {proxy_host}:{proxy_port} over TCP");

            let target = match &target_addr {
                crate::route::ProxyTarget::ResolvedLocally(ip) => {
                    TargetAddr::Ip((*ip, target_port.get()).into())
                }
                crate::route::ProxyTarget::ResolvedRemotely { name } => {
                    TargetAddr::Domain(Cow::Borrowed(name), target_port.get())
                }
            };

            let stream = super::super::StatelessDirect
                .connect(proxy, log_tag.clone())
                .await?;
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

struct ErrorForLog(tokio_socks::Error);

impl Display for ErrorForLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use tokio_socks::Error;
        match &self.0 {
            Error::Io(e) => write!(f, "IO error: {}", e.kind()),
            Error::ParseError(infallible) => match *infallible {},
            err_with_static_msg @ (Error::InvalidTargetAddress(msg)
            | Error::InvalidAuthValues(msg)) => {
                // Prove the lifetime is 'static, so this doesn't contain user data.
                let _msg: &'static str = msg;
                Display::fmt(err_with_static_msg, f)
            }
            e @ (Error::ProxyServerUnreachable
            | Error::InvalidResponseVersion
            | Error::NoAcceptableAuthMethods
            | Error::UnknownAuthMethod
            | Error::GeneralSocksServerFailure
            | Error::ConnectionNotAllowedByRuleset
            | Error::NetworkUnreachable
            | Error::HostUnreachable
            | Error::ConnectionRefused
            | Error::TtlExpired
            | Error::CommandNotSupported
            | Error::AddressTypeNotSupported
            | Error::UnknownError
            | Error::InvalidReservedByte
            | Error::UnknownAddressType
            | Error::AuthorizationRequired
            | Error::IdentdAuthFailure
            | Error::InvalidUserIdAuthFailure) => Display::fmt(e, f),
            e @ Error::PasswordAuthFailure(code) => {
                let _code: &u8 = code;
                Display::fmt(e, f)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use futures_util::{select, FutureExt as _};
    use test_case::test_matrix;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::join;

    use super::*;
    use crate::host::Host;
    use crate::tcp_ssl::proxy::testutil::{TcpServer, TlsServer, PROXY_HOSTNAME};
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
        async fn execute(&self, stream: &mut TcpStream) -> Self::Output {
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

    #[derive(Copy, Clone)]
    enum ResolveHostname {
        ResolveLocally,
        ResolveRemotely,
    }
    use Auth::*;
    use ResolveHostname::*;
    use TargetAddressType::*;

    #[test_matrix(
        (Authenticated, Unauthenticated),
        (HostnameTarget, IpTarget),
        (ResolveLocally, ResolveRemotely)
    )]
    #[tokio::test]
    async fn socks5_server_basic_e2e(
        auth: Auth,
        target_addr: TargetAddressType,
        resolve_hostname: ResolveHostname,
    ) {
        let proxy_credentials = match auth {
            Authenticated => Some((VALID_CREDS.0.to_owned(), VALID_CREDS.1.to_owned())),
            Unauthenticated => None,
        };
        let resolve_hostname_locally = match resolve_hostname {
            ResolveLocally => true,
            ResolveRemotely => false,
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

        let tls_server = TlsServer::new(TcpServer::bind_localhost(), &SERVER_CERTIFICATE);
        let target_host = match target_addr {
            HostnameTarget => Host::Domain(SERVER_HOSTNAME.into()),
            IpTarget => Host::Ip(tls_server.tcp.listen_addr.ip()),
        };
        let expected_client_target_addr = match (target_addr, resolve_hostname) {
            (HostnameTarget, ResolveRemotely) => socks5_server::proto::Address::DomainAddress(
                target_host.to_string().into(),
                tls_server.tcp.listen_addr.port(),
            ),
            _ => socks5_server::proto::Address::SocketAddress(tls_server.tcp.listen_addr),
        };
        let expected_dns_source = match (target_addr, resolve_hostname) {
            (HostnameTarget, ResolveLocally) => DnsSource::Static,
            (HostnameTarget, ResolveRemotely) => DnsSource::Delegated,
            (IpTarget, _) => DnsSource::Static,
        };

        let connector = SocksConnector {
            proxy_host: Host::Domain(PROXY_HOSTNAME.into()),
            proxy_port: NonZeroU16::new(proxy.0.local_addr().unwrap().port()).unwrap(),
            protocol: Protocol::Socks5 {
                username_password: proxy_credentials.clone(),
            },
            resolve_hostname_locally,
            dns_resolver: DnsResolver::new_from_static_map(HashMap::from([
                (PROXY_HOSTNAME, LookupResult::localhost()),
                (SERVER_HOSTNAME, LookupResult::localhost()),
            ])),
        };

        let connection_params = TransportConnectionParams {
            sni: SERVER_HOSTNAME.into(),
            tcp_host: target_host,
            port: NonZeroU16::new(tls_server.tcp.listen_addr.port()).unwrap(),
            certs: crate::certs::RootCertificates::FromDer(std::borrow::Cow::Borrowed(
                SERVER_CERTIFICATE.cert.der(),
            )),
        };
        let mut connect = connector.connect(&connection_params, Alpn::Http1_1);

        // Use `select!` to drive both futures since they both need to make
        // progress: the client needs to start connecting, and the proxy needs
        // to accept the incoming TCP connection.
        let proxy_server_connection = select! {
            connection = proxy.accept().fuse() => connection,
            _ = connect.as_mut().fuse() => unreachable!("client can't finish connection until the server accepts"),
        };

        // Start a task to handle the proxying. The proxy will connect
        // internally to the TLS server, then proxy until one or the other end
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
                    socks5_server::proto::Address::SocketAddress(tls_server.tcp.listen_addr),
                )
                .await
                .expect("can reply");

            let mut proxy_to_tls = tokio::net::TcpStream::connect(tls_server.tcp.listen_addr)
                .await
                .expect("can connect to TCP server");

            tokio::io::copy_bidirectional(&mut connection, &mut proxy_to_tls)
                .await
                .expect("ends gracefully");

            (auth_outcome, address)
        });

        let (
            (mut server_connection, _server_addr),
            StreamAndInfo(mut client_connection, client_info),
        ) = join!(
            tls_server.accept(),
            connect.map(|r| r.expect("connected successfully"))
        );

        assert_eq!(
            client_info,
            ServiceConnectionInfo {
                route_type: RouteType::SocksProxy,
                dns_source: expected_dns_source,
                address: Host::Ip(tls_server.tcp.listen_addr.ip())
            }
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

        let connector = SocksConnector {
            proxy_host: Host::Domain("localhost".into()),
            proxy_port: NonZeroU16::new(proxy.0.local_addr().unwrap().port()).unwrap(),
            protocol: Protocol::Socks5 {
                username_password: Some(proxy_credentials.clone()),
            },
            resolve_hostname_locally: true,
            dns_resolver: DnsResolver::new_from_static_map(HashMap::from([
                (SERVER_HOSTNAME, LookupResult::localhost()),
                ("localhost", LookupResult::localhost()),
            ])),
        };

        let connection_params = TransportConnectionParams {
            sni: SERVER_HOSTNAME.into(),
            tcp_host: Host::Domain(SERVER_HOSTNAME.into()),
            port: NonZeroU16::new(tls_server.tcp.listen_addr.port()).unwrap(),
            certs: crate::certs::RootCertificates::FromDer(std::borrow::Cow::Borrowed(
                SERVER_CERTIFICATE.cert.der(),
            )),
        };
        let connect = connector.connect(&connection_params, Alpn::Http1_1);

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
