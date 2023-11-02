//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;
use std::future::Future;
use std::num::ParseIntError;
use std::time::Duration;

use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_net::cdsi::{self, AciAndAccessKey, LookupResponse};
use libsignal_net::env::{CdsiEndpointConnection, Env};
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::{ConnectionParams, HttpRequestDecorator, HttpRequestDecoratorSeq};
use libsignal_protocol::{Aci, SignalProtocolError};

use crate::support::*;
use crate::*;

pub struct TokioAsyncContext(tokio::runtime::Runtime);

#[bridge_fn(ffi = false)]
fn TokioAsyncContext_new() -> TokioAsyncContext {
    TokioAsyncContext(tokio::runtime::Runtime::new().expect("failed to create runtime"))
}

impl<F: Future<Output = ()> + Send + 'static> AsyncRuntime<F> for TokioAsyncContext {
    fn run_future(&self, future: F) {
        #[allow(clippy::let_underscore_future)]
        let _: tokio::task::JoinHandle<()> = self.0.spawn(future);
    }
}

bridge_handle!(TokioAsyncContext, clone = false);

#[derive(num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum Environment {
    Staging = 0,
    Prod = 1,
}

impl Environment {
    fn env(&self) -> Env<'static> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }

    fn cdsi_fallback_connection_params(self) -> Vec<ConnectionParams> {
        match self {
            Environment::Prod => vec![
                ConnectionParams {
                    sni: "inbox.google.com".into(),
                    host: "reflector-nrgwuv7kwq-uc.a.run.app".into(),
                    port: 443,
                    http_request_decorator: HttpRequestDecorator::PathPrefix("/service").into(),
                    certs: RootCertificates::Native,
                    dns_resolver: DnsResolver::System,
                },
                ConnectionParams {
                    sni: "pintrest.com".into(),
                    host: "chat-signal.global.ssl.fastly.net".into(),
                    port: 443,
                    http_request_decorator: HttpRequestDecoratorSeq::default(),
                    certs: RootCertificates::Native,
                    dns_resolver: DnsResolver::System,
                },
            ],
            Environment::Staging => vec![ConnectionParams {
                sni: "inbox.google.com".into(),
                host: "reflector-nrgwuv7kwq-uc.a.run.app".into(),
                port: 443,
                http_request_decorator: HttpRequestDecorator::PathPrefix("/service-staging").into(),
                certs: RootCertificates::Native,
                dns_resolver: DnsResolver::System,
            }],
        }
    }
}

/// A sequence of [`ConnectionParams`] to try in order.
#[derive(Clone, Debug)]
pub struct ConnectionParamsList(Vec<ConnectionParams>);

pub struct ConnectionManager {
    cdsi: libsignal_net::env::CdsiEndpointConnection<MultiRouteConnectionManager>,
}

impl ConnectionManager {
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    fn new(environment: Environment) -> Self {
        let cdsi_endpoint = environment.env().cdsi;
        let direct_connection = cdsi_endpoint.direct_connection();
        let connection_params: Vec<_> = [direct_connection]
            .into_iter()
            .chain(environment.cdsi_fallback_connection_params())
            .collect();

        Self {
            cdsi: CdsiEndpointConnection::new_multi(
                cdsi_endpoint.mr_enclave,
                connection_params,
                Self::DEFAULT_CONNECT_TIMEOUT,
            ),
        }
    }
}

#[bridge_fn]
pub fn ConnectionManager_new(environment: u8) -> ConnectionManager {
    ConnectionManager::new(environment.try_into().expect("is valid environment value"))
}

bridge_handle!(ConnectionManager, clone = false);

#[derive(Default)]
pub struct LookupRequest(std::sync::Mutex<cdsi::LookupRequest>);

#[bridge_fn]
fn LookupRequest_new() -> LookupRequest {
    LookupRequest::default()
}

#[bridge_fn]
fn LookupRequest_addE164(request: &LookupRequest, e164: String) -> Result<(), SignalProtocolError> {
    let e164: libsignal_net::cdsi::E164 = e164.parse().map_err(|_: ParseIntError| {
        SignalProtocolError::InvalidArgument(format!("{e164} is not an e164"))
    })?;
    request.0.lock().expect("not poisoned").e164s.push(e164);
    Ok(())
}

#[bridge_fn]
fn LookupRequest_addAciAndAccessKey(
    request: &LookupRequest,
    aci: Aci,
    access_key: &[u8],
) -> Result<(), SignalProtocolError> {
    let access_key = access_key
        .try_into()
        .map_err(|_: std::array::TryFromSliceError| {
            SignalProtocolError::InvalidArgument(format!("access_key has wrong number of bytes"))
        })?;
    request
        .0
        .lock()
        .expect("not poisoned")
        .acis_and_access_keys
        .push(AciAndAccessKey { aci, access_key });
    Ok(())
}

#[bridge_fn(jni = false)]
fn LookupRequest_setReturnAcisWithoutUaks(
    request: &LookupRequest,
    return_acis_without_uaks: bool,
) -> Result<(), SignalProtocolError> {
    request
        .0
        .lock()
        .expect("not poisoned")
        .return_acis_without_uaks = return_acis_without_uaks;
    Ok(())
}

bridge_handle!(LookupRequest, clone = false);

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn CdsiLookup(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    request: &LookupRequest,
    timeout_millis: u32,
) -> Result<LookupResponse, cdsi::Error> {
    let request = std::mem::take(&mut *request.0.lock().expect("not poisoned"));

    cdsi::cdsi_lookup(
        cdsi::Auth { username, password },
        &connection_manager.cdsi,
        request,
        Duration::from_millis(timeout_millis.into()),
    )
    .await
}
