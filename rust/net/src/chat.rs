//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::{Debug, Display};
use std::sync::Arc;
use std::time::Duration;

use ::http::uri::PathAndQuery;
use ::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libsignal_net_infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net_infra::route::{
    Connector, HttpsTlsRoute, RouteProvider, RouteProviderExt, ThrottlingConnector, TransportRoute,
    UnresolvedHttpsServiceRoute, UnresolvedWebsocketServiceRoute, UsePreconnect, WebSocketRoute,
    WebSocketRouteFragment,
};
use libsignal_net_infra::timeouts::ONE_ROUTE_CONNECTION_TIMEOUT;
use libsignal_net_infra::utils::NetworkChangeEvent;
use libsignal_net_infra::ws::StreamWithResponseHeaders;
use libsignal_net_infra::{
    make_ws_config, AsHttpHeader, Connection, EndpointConnection, IpType, TransportInfo,
};
use tokio_tungstenite::WebSocketStream;

use crate::auth::Auth;
use crate::connect_state::{
    ConnectionResources, DefaultTransportConnector, RouteInfo, WebSocketTransportConnectorFactory,
};
use crate::env::{add_user_agent_header, ConnectionConfig, UserAgent};
use crate::proto;

mod error;
pub use error::{ConnectError, SendError};

pub mod fake;
pub mod noise;
pub mod server_requests;
pub mod ws;
pub mod ws2;

pub type MessageProto = proto::chat_websocket::WebSocketMessage;
pub type RequestProto = proto::chat_websocket::WebSocketRequestMessage;
pub type ResponseProto = proto::chat_websocket::WebSocketResponseMessage;
pub type ChatMessageType = proto::chat_websocket::web_socket_message::Type;

const RECEIVE_STORIES_HEADER_NAME: &str = "x-signal-receive-stories";

#[derive(Debug)]
pub struct DebugInfo {
    /// IP type of the connection that was used for the request.
    pub ip_type: Option<IpType>,
    /// Time it took to complete the request.
    pub duration: Duration,
    /// Connection information summary.
    pub connection_info: String,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Request {
    pub method: ::http::Method,
    pub body: Option<Box<[u8]>>,
    pub headers: HeaderMap,
    pub path: PathAndQuery,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Response {
    pub status: StatusCode,
    pub message: Option<String>,
    pub body: Option<Box<[u8]>>,
    pub headers: HeaderMap,
}

#[derive(Debug)]
pub struct ResponseProtoInvalidError;

impl TryFrom<ResponseProto> for Response {
    type Error = ResponseProtoInvalidError;

    fn try_from(response_proto: ResponseProto) -> Result<Self, Self::Error> {
        let status = response_proto
            .status()
            .try_into()
            .map_err(|_| ResponseProtoInvalidError)
            .and_then(|status_code| {
                StatusCode::from_u16(status_code).map_err(|_| ResponseProtoInvalidError)
            })?;
        let message = response_proto.message;
        let body = response_proto.body.map(|v| v.into_boxed_slice());
        let headers = response_proto.headers.into_iter().try_fold(
            HeaderMap::new(),
            |mut headers, header_string| {
                let (name, value) = header_string
                    .split_once(':')
                    .ok_or(ResponseProtoInvalidError)?;
                let header_name =
                    HeaderName::try_from(name).map_err(|_| ResponseProtoInvalidError)?;
                let header_value =
                    HeaderValue::from_str(value.trim()).map_err(|_| ResponseProtoInvalidError)?;
                headers.append(header_name, header_value);
                Ok(headers)
            },
        )?;
        Ok(Response {
            status,
            message,
            body,
            headers,
        })
    }
}

impl From<ResponseProtoInvalidError> for SendError {
    fn from(ResponseProtoInvalidError: ResponseProtoInvalidError) -> Self {
        Self::IncomingDataInvalid
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, derive_more::From)]
pub struct ReceiveStories(bool);

impl AsHttpHeader for ReceiveStories {
    const HEADER_NAME: HeaderName = HeaderName::from_static(RECEIVE_STORIES_HEADER_NAME);

    fn header_value(&self) -> HeaderValue {
        HeaderValue::from_static(if self.0 { "true" } else { "false" })
    }
}

pub fn endpoint_connection(
    connection_config: &ConnectionConfig,
    user_agent: &UserAgent,
    include_fallback: bool,
    network_change_event: &NetworkChangeEvent,
) -> EndpointConnection<MultiRouteConnectionManager> {
    let chat_endpoint = PathAndQuery::from_static(crate::env::constants::WEB_SOCKET_PATH);
    let chat_connection_params = if include_fallback {
        connection_config.connection_params_with_fallback()
    } else {
        vec![connection_config.direct_connection_params()]
    };
    let chat_connection_params = add_user_agent_header(chat_connection_params, user_agent);
    let chat_ws_config = make_ws_config(chat_endpoint, ONE_ROUTE_CONNECTION_TIMEOUT);
    EndpointConnection::new_multi(
        chat_connection_params,
        ONE_ROUTE_CONNECTION_TIMEOUT,
        chat_ws_config,
        network_change_event,
    )
}

/// Information about an established connection.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub route_info: RouteInfo,
    pub transport_info: TransportInfo,
}

pub struct ChatConnection {
    inner: self::ws2::Chat,
    connection_info: ConnectionInfo,
}

type ChatTransportConnection =
    <DefaultTransportConnector as Connector<TransportRoute, ()>>::Connection;

/// A connection to the chat service that isn't yet active.
///
/// Parameterized over the type of the transport-level connection for testing.
#[derive(Debug)]
pub struct PendingChatConnection<T = ChatTransportConnection> {
    connection: WebSocketStream<T>,
    connect_response_headers: http::HeaderMap,
    ws_config: ws2::Config,
    route_info: RouteInfo,
    log_tag: Arc<str>,
}

#[cfg_attr(test, derive(Clone))]
pub struct AuthenticatedChatHeaders {
    pub auth: Auth,
    pub receive_stories: ReceiveStories,
}

pub type ChatServiceRoute = UnresolvedWebsocketServiceRoute;

impl ChatConnection {
    pub async fn start_connect_with<TC>(
        connection_resources: ConnectionResources<'_, TC>,
        http_route_provider: impl RouteProvider<Route = UnresolvedHttpsServiceRoute>,
        user_agent: &UserAgent,
        ws_config: self::ws2::Config,
        auth: Option<AuthenticatedChatHeaders>,
        log_tag: &str,
    ) -> Result<PendingChatConnection, ConnectError>
    where
        TC: WebSocketTransportConnectorFactory<
            UsePreconnect<TransportRoute>,
            Connection = ChatTransportConnection,
        >,
    {
        Self::start_connect_with_transport(
            connection_resources,
            http_route_provider,
            user_agent,
            ws_config,
            auth,
            log_tag,
        )
        .await
    }

    #[cfg_attr(feature = "test-util", visibility::make(pub))]
    async fn start_connect_with_transport<TC>(
        connection_resources: ConnectionResources<'_, TC>,
        http_route_provider: impl RouteProvider<Route = UnresolvedHttpsServiceRoute>,
        user_agent: &UserAgent,
        ws_config: self::ws2::Config,
        auth: Option<AuthenticatedChatHeaders>,
        log_tag: &str,
    ) -> Result<PendingChatConnection<TC::Connection>, ConnectError>
    where
        TC: WebSocketTransportConnectorFactory<UsePreconnect<TransportRoute>>,
    {
        let should_preconnect = auth.is_some();
        let headers = auth
            .into_iter()
            .flat_map(
                |AuthenticatedChatHeaders {
                     auth,
                     receive_stories,
                 }| [auth.as_header(), receive_stories.as_header()],
            )
            .chain([user_agent.as_header()]);
        let ws_fragment = WebSocketRouteFragment {
            ws_config: Default::default(),
            endpoint: PathAndQuery::from_static(crate::env::constants::WEB_SOCKET_PATH),
            headers: HeaderMap::from_iter(headers),
        };

        let ws_routes = http_route_provider.map_routes(move |http| WebSocketRoute {
            inner: HttpsTlsRoute {
                inner: UsePreconnect {
                    should: should_preconnect,
                    inner: http.inner,
                },
                fragment: http.fragment,
            },
            fragment: ws_fragment.clone(),
        });

        let log_tag: Arc<str> = log_tag.into();
        let (connection, route_info) = connection_resources
            .connect_ws(
                ws_routes,
                // If we create multiple authenticated chat websocket connections at
                // the same time, the server will terminate earlier ones as later
                // ones complete. Throttling at the websocket connection level
                // lets us get connection parallelism at the transport level (which
                // is useful) while limiting us to one fully established connection
                // at a time.
                ThrottlingConnector::new(crate::infra::ws::Stateless, 1),
                log_tag.clone(),
            )
            .await?;

        // It's okay to discard the ThrottlingConnection layer here, because no other routes are
        // still connecting.
        let StreamWithResponseHeaders {
            stream,
            response_headers,
        } = connection.into_inner();

        Ok(PendingChatConnection {
            connection: stream,
            connect_response_headers: response_headers,
            route_info,
            ws_config,
            log_tag,
        })
    }

    pub fn finish_connect(
        tokio_runtime: tokio::runtime::Handle,
        pending: PendingChatConnection,
        listener: ws2::EventListener,
    ) -> Self {
        let PendingChatConnection {
            connection,
            connect_response_headers,
            ws_config,
            route_info,
            log_tag,
        } = pending;
        Self {
            connection_info: ConnectionInfo {
                route_info,
                transport_info: connection.transport_info(),
            },
            inner: ws2::Chat::new(
                tokio_runtime,
                connection,
                connect_response_headers,
                ws_config,
                log_tag,
                listener,
            ),
        }
    }

    pub async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, SendError> {
        let send_result = tokio::time::timeout(timeout, self.inner.send(msg))
            .await
            .map_err(|_elapsed| SendError::RequestTimedOut)?;
        Ok(send_result?)
    }

    pub async fn disconnect(&self) {
        self.inner.disconnect().await
    }

    pub fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info
    }
}

impl PendingChatConnection {
    pub fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            route_info: self.route_info.clone(),
            transport_info: self.connection.transport_info(),
        }
    }

    pub async fn disconnect(&mut self) {
        if let Err(error) = self.connection.close(None).await {
            log::error!(
                "[{}] pending chat connection disconnect failed with {error}",
                &self.log_tag
            );
        }
    }
}

impl Display for ConnectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            transport_info:
                TransportInfo {
                    local_port,
                    ip_version,
                },
            route_info,
        } = self;
        write!(f, "from {ip_version}:{local_port} via {route_info}")
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod test_support {

    use std::time::Duration;

    use libsignal_net_infra::dns::DnsResolver;
    use libsignal_net_infra::testutil::no_network_change_events;
    use libsignal_net_infra::EnableDomainFronting;

    use super::*;
    use crate::chat::{ws2, ChatConnection};
    use crate::connect_state::{
        ConnectState, DefaultConnectorFactory, PreconnectingFactory, SUGGESTED_CONNECT_CONFIG,
    };
    use crate::env::{Env, UserAgent};
    use crate::infra::route::DirectOrProxyProvider;

    pub async fn simple_chat_connection(
        env: &Env<'static>,
        enable_domain_fronting: EnableDomainFronting,
        filter_routes: impl Fn(&UnresolvedHttpsServiceRoute) -> bool,
    ) -> Result<ChatConnection, ConnectError> {
        let dns_resolver = DnsResolver::new_with_static_fallback(
            env.static_fallback(),
            &no_network_change_events(),
        );

        let route_provider = DirectOrProxyProvider::maybe_proxied(
            env.chat_domain_config
                .connect
                .route_provider(enable_domain_fronting),
            None,
        )
        .filter_routes(filter_routes);

        let connect = ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            PreconnectingFactory::new(DefaultConnectorFactory, Duration::ZERO),
        );
        let user_agent = UserAgent::with_libsignal_version("test_simple_chat_connection");

        let ws_config = ws2::Config {
            initial_request_id: 0,
            local_idle_timeout: Duration::from_secs(60),
            remote_idle_timeout: Duration::from_secs(60),
        };

        let connection_resources = ConnectionResources {
            connect_state: &connect,
            dns_resolver: &dns_resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: env
                .chat_domain_config
                .connect
                .confirmation_header_name
                .map(HeaderName::from_static),
        };

        let pending = ChatConnection::start_connect_with(
            connection_resources,
            route_provider,
            &user_agent,
            ws_config,
            None,
            "test",
        )
        .await?;

        // Just a no-op listener.
        let listener: ws2::EventListener = Box::new(|_event| {});

        let tokio_runtime = tokio::runtime::Handle::try_current().expect("can get tokio runtime");
        let chat_connection = ChatConnection::finish_connect(tokio_runtime, pending, listener);

        Ok(chat_connection)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::collections::HashMap;
    use std::sync::atomic::{self, AtomicU8};

    use assert_matches::assert_matches;
    use http::{HeaderName, HeaderValue};
    use itertools::Itertools;
    use libsignal_net_infra::certs::RootCertificates;
    use libsignal_net_infra::dns::lookup_result::LookupResult;
    use libsignal_net_infra::dns::DnsResolver;
    use libsignal_net_infra::errors::{RetryLater, TransportConnectError};
    use libsignal_net_infra::host::Host;
    use libsignal_net_infra::route::testutils::ConnectFn;
    use libsignal_net_infra::route::{
        DirectOrProxyRoute, HttpRouteFragment, HttpsTlsRoute, PreconnectingFactory, TcpRoute,
        TlsRoute, TlsRouteFragment, UnresolvedHost, DEFAULT_HTTPS_PORT,
    };
    use libsignal_net_infra::testutil::no_network_change_events;
    use libsignal_net_infra::ws::WebSocketConnectError;
    use libsignal_net_infra::Alpn;
    use test_case::test_case;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::connect_state::{ConnectState, SUGGESTED_CONNECT_CONFIG};

    #[test]
    fn proto_into_response_works_with_valid_data() {
        let expected_body = b"content";
        let expected_status = 200u16;
        let expected_host_value = "char.signal.org";
        let proto = ResponseProto {
            status: Some(expected_status.into()),
            headers: vec![format!("HOST: {}", expected_host_value)],
            body: Some(expected_body.to_vec()),
            message: None,
            id: None,
        };
        let response: Response = proto.try_into().unwrap();
        assert_eq!(expected_status, response.status.as_u16());
        assert_eq!(*expected_body, *response.body.unwrap());
        assert_eq!(
            expected_host_value,
            response
                .headers
                .get(http::header::HOST)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn proto_into_response_works_with_valid_data_and_no_body() {
        let expected_status = 200u16;
        let expected_host_value = "char.signal.org";
        let proto = ResponseProto {
            status: Some(expected_status.into()),
            headers: vec![format!("HOST: {}", expected_host_value)],
            body: None,
            message: None,
            id: None,
        };
        let response: Response = proto.try_into().unwrap();
        assert_eq!(expected_status, response.status.as_u16());
        assert_eq!(None, response.body);
        assert_eq!(
            expected_host_value,
            response
                .headers
                .get(http::header::HOST)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn proto_into_response_works_and_headers_parsed_correctly() {
        let proto = ResponseProto {
            status: Some(200),
            headers: vec![
                format!("{}: {}", http::header::FORWARDED.as_str(), "1.1.1.1"),
                format!("{}: {}", http::header::FORWARDED.as_str(), "2.2.2.2"),
                format!("{}: {}", http::header::HOST.as_str(), " chat.signal.org "),
                format!("{}: {}", http::header::USER_AGENT, ""),
            ],
            body: None,
            message: None,
            id: None,
        };
        let response: Response = proto.try_into().unwrap();

        fn values_to_vec(
            headers: &http::HeaderMap<HeaderValue>,
            header_name: HeaderName,
        ) -> Vec<&str> {
            headers
                .get_all(header_name)
                .into_iter()
                .map(|h| h.to_str().unwrap())
                .collect()
        }
        assert_eq!(
            vec![""],
            values_to_vec(&response.headers, http::header::USER_AGENT)
        );
        assert_eq!(
            vec!["chat.signal.org"],
            values_to_vec(&response.headers, http::header::HOST)
        );
        assert_eq!(
            vec!["1.1.1.1", "2.2.2.2"],
            values_to_vec(&response.headers, http::header::FORWARDED)
        );
    }

    #[test]
    fn proto_into_response_fails_for_invalid_data() {
        // status out of range of u16
        validate_invalid_data(Some(1 << 20), None, vec![]);
        // status in range, but value is invalid
        validate_invalid_data(Some(9999), None, vec![]);
        // status field is missing from the proto
        validate_invalid_data(None, None, vec![]);
        // header has an invalid value
        validate_invalid_data(Some(200), None, vec!["invalid header".to_string()]);
        validate_invalid_data(Some(200), None, vec!["invalid name: value".to_string()]);
        validate_invalid_data(Some(200), None, vec!["invalid_name : value".to_string()]);
        validate_invalid_data(Some(200), None, vec![" invalid_name: value".to_string()]);
    }

    fn validate_invalid_data(status: Option<u32>, body: Option<Vec<u8>>, headers: Vec<String>) {
        let proto = ResponseProto {
            status,
            headers,
            body,
            message: None,
            id: None,
        };
        let response: Result<Response, _> = proto.try_into();
        assert_matches!(response, Err(ResponseProtoInvalidError));
    }

    fn encode_response(response: http::Response<impl AsRef<[u8]>>) -> Vec<u8> {
        let mut result = vec![];
        assert_eq!(
            response.version(),
            http::Version::HTTP_11,
            "not set up to write any other kind of response"
        );
        result.extend(
            format!(
                "HTTP/1.1 {} {}\r\n",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or_default(),
            )
            .as_bytes(),
        );
        for (name, value) in response.headers() {
            result.extend([name.as_str().as_bytes(), b": ", value.as_bytes(), b"\r\n"].concat());
        }
        result.extend(b"\r\n");
        result.extend(response.body().as_ref());
        result
    }

    // It's easier to use this with test_case in string form.
    const CONFIRMATION_HEADER: &str = "x-really-signal";

    #[test_case(403, &[] => matches ConnectError::AllAttemptsFailed)]
    #[test_case(403, &[(CONFIRMATION_HEADER, "1")] => matches ConnectError::DeviceDeregistered)]
    #[test_case(499, &[(CONFIRMATION_HEADER, "1")] => matches ConnectError::AppExpired)]
    #[test_case(429, &[(CONFIRMATION_HEADER, "1"), ("retry-after", "20")] => matches ConnectError::RetryLater(RetryLater { retry_after_seconds: 20 }))]
    #[test_case(500, &[(CONFIRMATION_HEADER, "1"), ("retry-after", "20")] => matches ConnectError::RetryLater(RetryLater { retry_after_seconds: 20 }))]
    #[test_case(429, &[("retry-after", "20")] => matches ConnectError::AllAttemptsFailed)]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn html_status_tests(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
    ) -> ConnectError {
        let (client, mut server) = tokio::io::duplex(1024);

        let server_task = tokio::spawn(async move {
            // Ignore any request, just serve a hardcoded response.
            let mut response = http::Response::builder().status(status);
            for &(name, value) in headers {
                response
                    .headers_mut()
                    .expect("no errors yet")
                    .append(name, HeaderValue::from_static(value));
            }
            server
                .write_all(&encode_response(response.body([]).expect("valid")))
                .await
                .expect("can write");

            let mut ignored_request = vec![];
            server
                .read_to_end(&mut ignored_request)
                .await
                .expect("can read");
        });

        let client = std::sync::Mutex::new(Some(client));
        let connect_state = ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            ConnectFn(|_inner, _route, _log_tag| {
                std::future::ready(client.lock().expect("unpoisoned").take().ok_or(
                    WebSocketConnectError::Transport(TransportConnectError::TcpConnectionFailed),
                ))
            }),
        );

        const CHAT_DOMAIN: &str = "test.signal.org";
        let connection_resources = ConnectionResources {
            connect_state: &connect_state,
            dns_resolver: &DnsResolver::new_from_static_map(HashMap::from_iter([(
                CHAT_DOMAIN,
                LookupResult::localhost(),
            )])),
            network_change_event: &no_network_change_events(),
            confirmation_header_name: Some(HeaderName::from_static(CONFIRMATION_HEADER)),
        };

        let err = ChatConnection::start_connect_with_transport(
            connection_resources,
            vec![HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header: CHAT_DOMAIN.into(),
                    path_prefix: "".into(),
                    front_name: None,
                },
                inner: TlsRoute {
                    fragment: TlsRouteFragment {
                        root_certs: RootCertificates::Native,
                        sni: Host::Domain(CHAT_DOMAIN.into()),
                        alpn: Some(Alpn::Http1_1),
                    },
                    inner: DirectOrProxyRoute::Direct(TcpRoute {
                        address: UnresolvedHost(CHAT_DOMAIN.into()),
                        port: DEFAULT_HTTPS_PORT,
                    }),
                },
            }],
            &UserAgent::with_libsignal_version("test"),
            ws2::Config {
                // We shouldn't get to timing out anyway.
                local_idle_timeout: Duration::ZERO,
                remote_idle_timeout: Duration::ZERO,
                initial_request_id: 0,
            },
            None,
            "fake chat",
        )
        .await
        .expect_err("should fail to connect");

        server_task.await.expect("clean exit");

        err
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn preconnect_same_route() {
        let number_of_times_called = AtomicU8::new(0);

        let inner_connector = ConnectFn(|_inner, _route, _log_tag| {
            // This acts like a successful TLS connection to a server that immediately closes
            // the connection before sending anything.
            let (client, _server) = tokio::io::duplex(1024);
            number_of_times_called.fetch_add(1, atomic::Ordering::SeqCst);
            std::future::ready(Ok::<_, TransportConnectError>(client))
        });
        let transport_connector =
            PreconnectingFactory::new(inner_connector, Duration::from_secs(1));

        let connect_state = ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            transport_connector,
        );

        let dns_resolver = DnsResolver::new_from_static_map(HashMap::from_iter([(
            CHAT_DOMAIN,
            LookupResult::localhost(),
        )]));

        const CHAT_DOMAIN: &str = "test.signal.org";
        let routes = vec![HttpsTlsRoute {
            fragment: HttpRouteFragment {
                host_header: CHAT_DOMAIN.into(),
                path_prefix: "".into(),
                front_name: None,
            },
            inner: TlsRoute {
                fragment: TlsRouteFragment {
                    root_certs: RootCertificates::Native,
                    sni: Host::Domain(CHAT_DOMAIN.into()),
                    alpn: Some(Alpn::Http1_1),
                },
                inner: DirectOrProxyRoute::Direct(TcpRoute {
                    address: UnresolvedHost(CHAT_DOMAIN.into()),
                    port: DEFAULT_HTTPS_PORT,
                }),
            },
        }];

        let network_change_event = no_network_change_events();
        let make_connection_resources = || ConnectionResources {
            connect_state: &connect_state,
            dns_resolver: &dns_resolver,
            network_change_event: &network_change_event,
            confirmation_header_name: Some(HeaderName::from_static(CONFIRMATION_HEADER)),
        };

        make_connection_resources()
            .preconnect_and_save(
                routes
                    .iter()
                    .cloned()
                    .map(|route| route.inner)
                    .collect_vec(),
                "preconnect".into(),
            )
            .await
            .expect("success");

        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);

        // ChatConnection only uses the preconnect for auth connections
        let auth_headers = AuthenticatedChatHeaders {
            auth: Auth {
                username: "user".into(),
                password: "****".into(),
            },
            receive_stories: ReceiveStories(true),
        };

        let err = ChatConnection::start_connect_with_transport(
            make_connection_resources(),
            routes.clone(),
            &UserAgent::with_libsignal_version("test"),
            ws2::Config {
                // We shouldn't get to timing out anyway.
                local_idle_timeout: Duration::ZERO,
                remote_idle_timeout: Duration::ZERO,
                initial_request_id: 0,
            },
            Some(auth_headers.clone()),
            "fake chat",
        )
        .await
        .expect_err("should fail to connect");

        assert_matches!(err, ConnectError::AllAttemptsFailed);
        // 1 preconnect that subsequently fails, 1 IPv4 follow-up connection that also fails.
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 2);

        let err = ChatConnection::start_connect_with_transport(
            make_connection_resources(),
            routes.clone(),
            &UserAgent::with_libsignal_version("test"),
            ws2::Config {
                // We shouldn't get to timing out anyway.
                local_idle_timeout: Duration::ZERO,
                remote_idle_timeout: Duration::ZERO,
                initial_request_id: 0,
            },
            Some(auth_headers),
            "fake chat",
        )
        .await
        .expect_err("should fail to connect");

        assert_matches!(err, ConnectError::AllAttemptsFailed);
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 4);
    }
}
