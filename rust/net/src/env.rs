//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;
use std::time::Duration;

use hex_literal::hex;
use http::uri::PathAndQuery;

use crate::cdsi::CdsiConnectionParams;
use crate::infra::certs::RootCertificates;
use crate::infra::connection_manager::{
    ConnectionManager, MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use crate::infra::dns::DnsResolver;
use crate::infra::{ConnectionParams, HttpRequestDecoratorSeq};

#[derive(Copy, Clone)]
pub struct CdsiEndpointMrEnclave<B>(B);

impl<B: AsRef<[u8]>> CdsiEndpointMrEnclave<B> {
    pub fn path(&self) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}/discovery", hex::encode(self.0.as_ref()))).unwrap()
    }
}

#[derive(Copy, Clone)]
pub struct CdsiEndpoint<'a> {
    pub host: &'a str,
    pub mr_enclave: CdsiEndpointMrEnclave<&'a [u8]>,
}

impl CdsiEndpoint<'_> {
    pub fn direct_connection(&self) -> ConnectionParams {
        let host: Arc<str> = Arc::from(self.host);
        ConnectionParams {
            sni: host.clone(),
            host,
            port: 443,
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            certs: RootCertificates::Signal,
            dns_resolver: DnsResolver::System,
        }
    }
}

pub struct CdsiEndpointConnection<C> {
    mr_enclave: CdsiEndpointMrEnclave<&'static [u8]>,
    connection_manager: C,
}

impl CdsiEndpointConnection<SingleRouteThrottlingConnectionManager> {
    pub fn new(cdsi: CdsiEndpoint<'static>, connect_timeout: Duration) -> Self {
        Self {
            connection_manager: SingleRouteThrottlingConnectionManager::new(
                cdsi.direct_connection(),
                connect_timeout,
            ),
            mr_enclave: cdsi.mr_enclave,
        }
    }
}

impl CdsiEndpointConnection<MultiRouteConnectionManager> {
    pub fn new_multi(
        mr_enclave: CdsiEndpointMrEnclave<&'static [u8]>,
        connection_params: impl IntoIterator<Item = ConnectionParams>,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            connection_manager: MultiRouteConnectionManager::new(
                connection_params
                    .into_iter()
                    .map(|params| {
                        SingleRouteThrottlingConnectionManager::new(params, connect_timeout)
                    })
                    .collect(),
                connect_timeout,
            ),
            mr_enclave,
        }
    }
}

impl<C: ConnectionManager> CdsiConnectionParams for CdsiEndpointConnection<C> {
    type ConnectionManager = C;

    fn connection_manager(&self) -> &Self::ConnectionManager {
        &self.connection_manager
    }

    fn endpoint(&self) -> PathAndQuery {
        self.mr_enclave.path()
    }

    fn mr_enclave(&self) -> &[u8] {
        self.mr_enclave.0
    }
}

pub struct Env<'a> {
    pub cdsi: CdsiEndpoint<'a>,
    pub chat_host: &'a str,
}

pub const STAGING: Env<'static> = Env {
    chat_host: "chat.staging.signal.org",
    cdsi: CdsiEndpoint {
        host: "cdsi.staging.signal.org",
        mr_enclave: CdsiEndpointMrEnclave(&hex!(
            "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57"
        )),
    },
};

pub const PROD: Env<'static> = Env {
    chat_host: "chat.signal.org",
    cdsi: CdsiEndpoint {
        host: "cdsi.signal.org",
        mr_enclave: CdsiEndpointMrEnclave(&hex!(
            "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57"
        )),
    },
};

pub mod constants {
    pub(crate) const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}
