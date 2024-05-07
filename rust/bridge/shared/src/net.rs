//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;
use std::num::{NonZeroU16, NonZeroU32};
use std::panic::RefUnwindSafe;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ::tokio::sync::mpsc;
use base64::prelude::{Engine, BASE64_STANDARD};
use futures_util::future::TryFutureExt as _;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_net::auth::Auth;
use libsignal_net::chat::{
    chat_service, ChatServiceError, ChatServiceWithDebugInfo, DebugInfo as ChatServiceDebugInfo,
    Request, Response as ChatResponse,
};
use libsignal_net::enclave::{
    Cdsi, EnclaveEndpoint, EnclaveEndpointConnection, EnclaveKind, Nitro, PpssSetup, Sgx, Tpm2Snp,
};
use libsignal_net::env::{add_user_agent_header, Env, Svr3Env};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::{
    DirectConnector as TcpSslDirectConnector, TcpSslConnector, TcpSslConnectorStream,
};
use libsignal_net::infra::{make_ws_config, EndpointConnection};
use libsignal_net::svr::{self, SvrConnection};
use libsignal_net::svr3::{self, OpaqueMaskedShareSet, PpssOps as _};
use libsignal_net::{chat, env};
use rand::rngs::OsRng;

use crate::support::*;
use crate::*;

pub(crate) mod cdsi;
mod tokio;

pub use tokio::TokioAsyncContext;

#[derive(num_enum::TryFromPrimitive)]
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Environment {
    Staging = 0,
    Prod = 1,
}

impl Environment {
    fn env<'a>(self) -> Env<'a, Svr3Env<'a>> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }
}

pub struct ConnectionManager {
    chat: EndpointConnection<MultiRouteConnectionManager>,
    cdsi: EnclaveEndpointConnection<Cdsi, MultiRouteConnectionManager>,
    svr3: (
        EnclaveEndpointConnection<Sgx, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Nitro, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Tpm2Snp, MultiRouteConnectionManager>,
    ),
    transport_connector: std::sync::Mutex<TcpSslConnector>,
}

impl RefUnwindSafe for ConnectionManager {}

impl ConnectionManager {
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    fn new(environment: Environment, user_agent: String) -> Self {
        let dns_resolver =
            DnsResolver::new_with_static_fallback(environment.env().static_fallback());
        let transport_connector =
            std::sync::Mutex::new(TcpSslDirectConnector::new(dns_resolver).into());
        let chat_endpoint = PathAndQuery::from_static(env::constants::WEB_SOCKET_PATH);
        let chat_connection_params = environment
            .env()
            .chat_domain_config
            .connection_params_with_fallback();
        let chat_connection_params = add_user_agent_header(chat_connection_params, &user_agent);
        let chat_ws_config = make_ws_config(chat_endpoint, Self::DEFAULT_CONNECT_TIMEOUT);
        Self {
            chat: EndpointConnection::new_multi(
                chat_connection_params,
                Self::DEFAULT_CONNECT_TIMEOUT,
                chat_ws_config,
            ),
            cdsi: Self::endpoint_connection(&environment.env().cdsi, &user_agent),
            svr3: (
                Self::endpoint_connection(environment.env().svr3.sgx(), &user_agent),
                Self::endpoint_connection(environment.env().svr3.nitro(), &user_agent),
                Self::endpoint_connection(environment.env().svr3.tpm2snp(), &user_agent),
            ),
            transport_connector,
        }
    }

    fn endpoint_connection<E: EnclaveKind>(
        endpoint: &EnclaveEndpoint<'static, E>,
        user_agent: &str,
    ) -> EnclaveEndpointConnection<E, MultiRouteConnectionManager> {
        let params = endpoint.domain_config.connection_params_with_fallback();
        let params = add_user_agent_header(params, user_agent);
        EnclaveEndpointConnection::new_multi(
            endpoint.mr_enclave,
            params,
            Self::DEFAULT_CONNECT_TIMEOUT,
        )
    }
}

#[bridge_fn]
fn ConnectionManager_new(
    environment: AsType<Environment, u8>,
    user_agent: String,
) -> ConnectionManager {
    ConnectionManager::new(environment.into_inner(), user_agent)
}

#[bridge_fn]
fn ConnectionManager_set_proxy(
    connection_manager: &ConnectionManager,
    host: String,
    port: AsType<NonZeroU16, u16>,
) {
    let port = port.into_inner();
    let proxy_addr = (host.as_str(), port);
    let mut guard = connection_manager
        .transport_connector
        .lock()
        .expect("not poisoned");
    match &mut *guard {
        TcpSslConnector::Direct(direct) => *guard = direct.with_proxy(proxy_addr).into(),
        TcpSslConnector::Proxied(proxied) => proxied.set_proxy(proxy_addr),
    };
}

#[bridge_fn]
fn ConnectionManager_clear_proxy(connection_manager: &ConnectionManager) {
    let mut guard = connection_manager
        .transport_connector
        .lock()
        .expect("not poisoned");
    match &*guard {
        TcpSslConnector::Direct(_direct) => (),
        TcpSslConnector::Proxied(proxied) => {
            *guard = TcpSslDirectConnector::new(proxied.dns_resolver.clone()).into()
        }
    };
}

#[bridge_fn(jni = false, ffi = false)]
fn ConnectionManager_set_ipv6_enabled(connection_manager: &ConnectionManager, ipv6_enabled: bool) {
    let mut guard = connection_manager
        .transport_connector
        .lock()
        .expect("not poisoned");
    guard.set_ipv6_enabled(ipv6_enabled);
}

bridge_handle!(ConnectionManager, clone = false);

#[bridge_fn]
fn CreateOTP(username: String, secret: &[u8]) -> String {
    Auth::otp(&username, secret, std::time::SystemTime::now())
}

#[bridge_fn]
fn CreateOTPFromBase64(username: String, secret: String) -> String {
    let secret = BASE64_STANDARD.decode(secret).expect("valid base64");
    Auth::otp(&username, &secret, std::time::SystemTime::now())
}

#[bridge_io(TokioAsyncContext)]
async fn Svr3Backup(
    connection_manager: &ConnectionManager,
    secret: Box<[u8]>,
    password: String,
    max_tries: AsType<NonZeroU32, u32>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
) -> Result<Vec<u8>, svr3::Error> {
    let secret = secret
        .as_ref()
        .try_into()
        .expect("can only backup 32 bytes");
    let mut rng = OsRng;
    let share_set = svr3_connect(connection_manager, username, enclave_password)
        .map_err(|err| err.into())
        .and_then(|connections| {
            Svr3Env::backup(
                connections,
                &password,
                secret,
                max_tries.into_inner(),
                &mut rng,
            )
        })
        .await?;
    Ok(share_set.serialize().expect("can serialize the share set"))
}

#[bridge_io(TokioAsyncContext)]
async fn Svr3Restore(
    connection_manager: &ConnectionManager,
    password: String,
    share_set: Box<[u8]>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
) -> Result<Vec<u8>, svr3::Error> {
    let mut rng = OsRng;
    let share_set = OpaqueMaskedShareSet::deserialize(&share_set)?;
    let restored_secret = svr3_connect(connection_manager, username, enclave_password)
        .map_err(|err| err.into())
        .and_then(|connections| Svr3Env::restore(connections, &password, share_set, &mut rng))
        .await?;
    Ok(restored_secret.to_vec())
}

async fn svr3_connect<'a>(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<<Svr3Env<'a> as PpssSetup<TcpSslConnectorStream>>::Connections, svr::Error> {
    let auth = Auth { username, password };
    let ConnectionManager {
        chat: _chat,
        cdsi: _cdsi,
        svr3: (sgx, nitro, tpm2snp),
        transport_connector,
    } = connection_manager;
    let transport_connector = transport_connector.lock().expect("not poisoned").clone();
    let sgx = SvrConnection::connect(auth.clone(), sgx, transport_connector.clone()).await?;
    let nitro = SvrConnection::connect(auth.clone(), nitro, transport_connector.clone()).await?;
    let tpm2snp = SvrConnection::connect(auth, tpm2snp, transport_connector).await?;
    Ok((sgx, nitro, tpm2snp))
}

pub struct Chat {
    service: chat::Chat<
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
    >,
}

impl RefUnwindSafe for Chat {}

pub struct HttpRequest {
    pub method: http::Method,
    pub path: PathAndQuery,
    pub body: Option<Box<[u8]>>,
    pub headers: std::sync::Mutex<HeaderMap>,
}

pub struct ResponseAndDebugInfo {
    pub response: ChatResponse,
    pub debug_info: ChatServiceDebugInfo,
}

bridge_handle!(Chat, clone = false);
bridge_handle!(HttpRequest, clone = false);

/// Newtype wrapper for implementing [`TryFrom`]`
struct HttpMethod(http::Method);

impl TryFrom<String> for HttpMethod {
    type Error = <http::Method as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value).map(Self)
    }
}

fn http_request_new_impl(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: Option<&[u8]>,
) -> Result<HttpRequest, InvalidUri> {
    let body = body_as_slice.map(|slice| slice.to_vec().into_boxed_slice());
    let method = method.into_inner().0;
    let path = path.try_into()?;
    Ok(HttpRequest {
        method,
        path,
        body,
        headers: Default::default(),
    })
}

#[bridge_fn(ffi = false)]
fn HttpRequest_new(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: Option<&[u8]>,
) -> Result<HttpRequest, InvalidUri> {
    http_request_new_impl(method, path, body_as_slice)
}

#[bridge_fn(jni = false, node = false)]
fn HttpRequest_new_with_body(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: &[u8],
) -> Result<HttpRequest, InvalidUri> {
    http_request_new_impl(method, path, Some(body_as_slice))
}

#[bridge_fn(jni = false, node = false)]
fn HttpRequest_new_without_body(
    method: AsType<HttpMethod, String>,
    path: String,
) -> Result<HttpRequest, InvalidUri> {
    http_request_new_impl(method, path, None)
}

#[bridge_fn]
fn HttpRequest_add_header(
    request: &HttpRequest,
    name: AsType<HeaderName, String>,
    value: AsType<HeaderValue, String>,
) {
    let mut guard = request.headers.lock().expect("not poisoned");
    let header_key = name.into_inner();
    let header_value = value.into_inner();
    (*guard).append(header_key, header_value);
}

#[bridge_fn]
fn ChatService_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Chat {
    let (incoming_tx, _incoming_rx) = mpsc::channel(1);
    Chat {
        service: chat_service(
            &connection_manager.chat,
            connection_manager
                .transport_connector
                .lock()
                .expect("not poisoned")
                .clone(),
            incoming_tx,
            username,
            password,
        )
        .into_dyn(),
    }
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_disconnect(chat: &Chat) {
    chat.service.disconnect().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_connect_unauth(chat: &Chat) -> Result<ChatServiceDebugInfo, ChatServiceError> {
    chat.service.connect_unauthenticated().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_connect_auth(chat: &Chat) -> Result<ChatServiceDebugInfo, ChatServiceError> {
    chat.service.connect_authenticated().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_unauth_send(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ChatResponse, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    chat.service
        .send_unauthenticated(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_unauth_send_and_debug(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ResponseAndDebugInfo, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    let (result, debug_info) = chat
        .service
        .send_unauthenticated_and_debug(request, Duration::from_millis(timeout_millis.into()))
        .await;

    result.map(|response| ResponseAndDebugInfo {
        response,
        debug_info,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    use test_case::test_case;

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(env, "test-user-agent".to_string());
    }
}
