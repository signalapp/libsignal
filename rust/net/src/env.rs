//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::iter;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::sync::Arc;

use const_str::ip_addr;
use libsignal_net_infra::certs::RootCertificates;
use libsignal_net_infra::dns::lookup_result::LookupResult;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::{
    ConnectionParams, DnsSource, HttpRequestDecorator, HttpRequestDecoratorSeq, RouteType,
    TransportConnectionParams,
};
use nonzero_ext::nonzero;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

use crate::certs::{PROXY_G_ROOT_CERTIFICATES, SIGNAL_ROOT_CERTIFICATES};
use crate::enclave::{
    Cdsi, EnclaveEndpoint, EndpointParams, MrEnclave, Nitro, Sgx, SgxPreQuantum, Tpm2Snp,
};

const DEFAULT_HTTPS_PORT: NonZeroU16 = nonzero!(443_u16);
pub const TIMESTAMP_HEADER_NAME: &str = "x-signal-timestamp";
pub const RECEIVE_STORIES_HEADER_NAME: &str = "x-signal-receive-stories";

const DOMAIN_CONFIG_CHAT: DomainConfig = DomainConfig {
    ip_v4: &[
        ip_addr!(v4, "76.223.92.165"),
        ip_addr!(v4, "13.248.212.111"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2600:9000:a507:ab6d:4ce3:2f58:25d7:9cbf"),
        ip_addr!(v6, "2600:9000:a61f:527c:d5eb:a431:5239:3232"),
    ],
    connect: ConnectionConfig {
        hostname: "chat.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: Some(TIMESTAMP_HEADER_NAME),
        proxy: ConnectionProxyConfig {
            path_prefix: "/service",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        },
    },
};

const DOMAIN_CONFIG_CHAT_STAGING: DomainConfig = DomainConfig {
    ip_v4: &[
        ip_addr!(v4, "76.223.72.142"),
        ip_addr!(v4, "13.248.206.115"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2600:9000:a507:ab6d:7b25:2580:8bd6:3b93"),
        ip_addr!(v6, "2600:9000:a61f:527c:2215:cd9:bac6:a2f8"),
    ],
    connect: ConnectionConfig {
        hostname: "chat.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: Some(TIMESTAMP_HEADER_NAME),
        proxy: ConnectionProxyConfig {
            path_prefix: "/service-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        },
    },
};

const DOMAIN_CONFIG_CDSI: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "cdsi.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/cdsi",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "40.122.45.194")],
    ip_v6: &[ip_addr!(v6, "2603:1030:7::1")],
};

const DOMAIN_CONFIG_CDSI_STAGING: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "cdsi.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/cdsi-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "104.43.162.137")],
    ip_v6: &[ip_addr!(v6, "2603:1030:7::732")],
};

const DOMAIN_CONFIG_SVR2: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "svr2.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr2",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "20.66.40.69")],
    ip_v6: &[],
};

const DOMAIN_CONFIG_SVR2_STAGING: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "svr2.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr2-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "20.253.229.239")],
    ip_v6: &[],
};

const DOMAIN_CONFIG_SVR3_SGX: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "backend1.svr3.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr3-sgx",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "40.112.138.96")],
    ip_v6: &[],
};

const DOMAIN_CONFIG_SVR3_SGX_STAGING: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "backend1.svr3.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr3-sgx-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "13.88.63.29")],
    ip_v6: &[],
};

const DOMAIN_CONFIG_SVR3_NITRO: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "backend2.svr3.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr3-nitro",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "75.2.91.98")],
    ip_v6: &[],
};

const DOMAIN_CONFIG_SVR3_NITRO_STAGING: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "backend2.svr3.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr3-nitro-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "75.2.86.85"), ip_addr!(v4, "99.83.239.137")],
    ip_v6: &[],
};

pub const DOMAIN_CONFIG_SVR3_TPM2SNP: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "backend3.svr3.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr3-tpm2snp",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "34.144.241.251")],
    ip_v6: &[],
};

pub const DOMAIN_CONFIG_SVR3_TPM2SNP_STAGING: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "backend3.svr3.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: ConnectionProxyConfig {
            path_prefix: "/svr3-tpm2snp-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        },
    },
    ip_v4: &[ip_addr!(v4, "13.88.30.76")],
    ip_v6: &[],
};

pub const PROXY_CONFIG_F_PROD: ProxyConfig = ProxyConfig {
    route_type: RouteType::ProxyF,
    http_host: "reflector-signal.global.ssl.fastly.net",
    sni_list: &["splashthat.com", "slate.com", "www.redditstatic.com"],
    certs: RootCertificates::Native,
};

pub const PROXY_CONFIG_F_STAGING: ProxyConfig = ProxyConfig {
    route_type: RouteType::ProxyF,
    http_host: "reflector-staging-signal.global.ssl.fastly.net",
    sni_list: &["splashthat.com", "slate.com", "www.redditstatic.com"],
    certs: RootCertificates::Native,
};

pub const PROXY_CONFIG_G: ProxyConfig = ProxyConfig {
    route_type: RouteType::ProxyG,
    http_host: "reflector-nrgwuv7kwq-uc.a.run.app",
    sni_list: &[
        "www.google.com",
        "android.clients.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "inbox.google.com",
    ],
    certs: PROXY_G_ROOT_CERTIFICATES,
};

pub(crate) const ENDPOINT_PARAMS_CDSI_STAGING: EndpointParams<'static, Cdsi> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_STAGING_AND_PROD),
    raft_config: (),
};

pub(crate) const ENDPOINT_PARAMS_SVR2_STAGING: EndpointParams<'static, SgxPreQuantum> =
    EndpointParams {
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_STAGING),
        raft_config: attest::constants::RAFT_CONFIG_SVR2_STAGING,
    };
pub(crate) const ENDPOINT_PARAMS_SVR3_SGX_STAGING: EndpointParams<'static, Sgx> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_SGX_STAGING),
    raft_config: attest::constants::RAFT_CONFIG_SVR3_SGX_STAGING,
};
pub(crate) const ENDPOINT_PARAMS_SVR3_NITRO_STAGING: EndpointParams<'static, Nitro> =
    EndpointParams {
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_NITRO_STAGING),
        raft_config: attest::constants::RAFT_CONFIG_SVR3_NITRO_STAGING,
    };
pub(crate) const ENDPOINT_PARAMS_SVR3_TPM2SNP_STAGING: EndpointParams<'static, Tpm2Snp> =
    EndpointParams {
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_TPM2SNP_STAGING),
        raft_config: attest::constants::RAFT_CONFIG_SVR3_TPM2SNP_STAGING,
    };

pub(crate) const ENDPOINT_PARAMS_CDSI_PROD: EndpointParams<'static, Cdsi> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_STAGING_AND_PROD),
    raft_config: (),
};
pub(crate) const ENDPOINT_PARAMS_SVR2_PROD: EndpointParams<'static, SgxPreQuantum> =
    EndpointParams {
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_PROD),
        raft_config: attest::constants::RAFT_CONFIG_SVR2_PROD,
    };
pub(crate) const ENDPOINT_PARAMS_SVR3_SGX_PROD: EndpointParams<'static, Sgx> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_SGX_PROD),
    raft_config: attest::constants::RAFT_CONFIG_SVR3_SGX_PROD,
};
pub(crate) const ENDPOINT_PARAMS_SVR3_NITRO_PROD: EndpointParams<'static, Nitro> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_NITRO_PROD),
    raft_config: attest::constants::RAFT_CONFIG_SVR3_NITRO_PROD,
};
pub(crate) const ENDPOINT_PARAMS_SVR3_TPM2SNP_PROD: EndpointParams<'static, Tpm2Snp> =
    EndpointParams {
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_TPM2SNP_PROD),
        raft_config: attest::constants::RAFT_CONFIG_SVR3_TPM2SNP_PROD,
    };

/// Configuration for a target network resource, like `chat.signal.org`.
#[derive(Clone)]
pub struct DomainConfig {
    /// The portions of the config used during connection attempts.
    pub connect: ConnectionConfig,
    /// Static IPv4 addresses to try if domain name resolution fails.
    pub ip_v4: &'static [Ipv4Addr],
    /// Static IPv6 addresses to try if domain name resolution fails.
    pub ip_v6: &'static [Ipv6Addr],
}

#[derive(Clone)]
pub struct ConnectionConfig {
    /// The domain name of the resource.
    pub hostname: &'static str,
    /// The port for the resource.
    pub port: NonZeroU16,
    /// Which certificates to use when connecting to the resource.
    pub cert: RootCertificates,
    /// A header to look for that indicates that the resource was reached.
    ///
    /// If this is `Some()`, then the presence of the header in an HTTP response
    /// indicates that the response came from the resource, not from a proxy or
    /// load balancer.
    pub confirmation_header_name: Option<&'static str>,

    /// Additional configuration for connecting to the resource through a proxy
    /// if a direct connection fails.
    pub proxy: ConnectionProxyConfig,
}

#[derive(Clone)]
pub struct ConnectionProxyConfig {
    /// A path prefix to prepend to any requests sent through the proxy.
    pub path_prefix: &'static str,
    /// The addresses for the proxies.
    pub configs: [ProxyConfig; 2],
}

impl DomainConfig {
    pub fn static_fallback(&self) -> (&'static str, LookupResult) {
        (
            self.connect.hostname,
            LookupResult::new(DnsSource::Static, self.ip_v4.into(), self.ip_v6.into()),
        )
    }
}

impl ConnectionConfig {
    pub fn direct_connection_params(&self) -> ConnectionParams {
        let result = {
            let hostname = self.hostname.into();
            ConnectionParams {
                route_type: RouteType::Direct,
                transport: TransportConnectionParams {
                    sni: Arc::clone(&hostname),
                    tcp_host: Host::Domain(Arc::clone(&hostname)),
                    port: self.port,
                    certs: self.cert.clone(),
                },
                http_host: hostname,
                http_request_decorator: HttpRequestDecoratorSeq::default(),
                connection_confirmation_header: None,
            }
        };
        if let Some(header) = &self.confirmation_header_name {
            return result.with_confirmation_header(http::HeaderName::from_static(header));
        }
        result
    }

    pub fn connection_params_with_fallback(&self) -> Vec<ConnectionParams> {
        let direct = self.direct_connection_params();
        let mut rng = thread_rng();
        // TODO use array::each_ref() once MSRV >= 1.77
        let [params_a, params_b] = &self.proxy.configs;
        let [params_a, params_b] = [params_a, params_b].map(|config| {
            config.shuffled_connection_params(
                self.proxy.path_prefix,
                self.confirmation_header_name,
                &mut rng,
            )
        });

        let proxy_params = itertools::interleave(params_a, params_b);
        iter::once(direct).chain(proxy_params).collect()
    }
}

pub fn add_user_agent_header(
    mut connection_params_list: Vec<ConnectionParams>,
    user_agent: &str,
) -> Vec<ConnectionParams> {
    let with_lib_version = format!("{} libsignal/{}", user_agent, libsignal_core::VERSION);
    connection_params_list.iter_mut().for_each(|cp| {
        cp.http_request_decorator.add(HttpRequestDecorator::header(
            http::header::USER_AGENT,
            http::header::HeaderValue::try_from(&with_lib_version).expect("valid header string"),
        ));
    });
    connection_params_list
}

#[derive(Clone)]
pub struct ProxyConfig {
    route_type: RouteType,
    /// The value of the HTTP Host header
    http_host: &'static str,
    /// Domain names to use for DNS resolution and TLS SNI.
    sni_list: &'static [&'static str],
    /// TLS root certificates to use.
    certs: RootCertificates,
}

impl ProxyConfig {
    pub fn shuffled_connection_params(
        &self,
        proxy_path: &'static str,
        confirmation_header_name: Option<&'static str>,
        rng: &mut impl Rng,
    ) -> impl Iterator<Item = ConnectionParams> {
        let route_type = self.route_type;
        let http_host = Arc::from(self.http_host);
        let certs = self.certs.clone();

        let mut sni_list = self.sni_list.to_vec();
        sni_list.shuffle(rng);

        sni_list.into_iter().map(move |sni| {
            // We want to use the SNI name as the hostname for DNS lookup and
            // for the TLS connection. Then, once an encrypted connection is
            // established, the actual hostname should be used for the HTTP
            // header.
            let sni_and_dns_host = (*sni).into();
            ConnectionParams {
                route_type,
                transport: TransportConnectionParams {
                    sni: Arc::clone(&sni_and_dns_host),
                    tcp_host: Host::Domain(sni_and_dns_host),
                    port: nonzero!(443u16),
                    certs: certs.clone(),
                },
                http_host: Arc::clone(&http_host),
                http_request_decorator: HttpRequestDecorator::PathPrefix(proxy_path).into(),
                connection_confirmation_header: confirmation_header_name
                    .map(http::HeaderName::from_static),
            }
        })
    }
}

pub struct Env<'a, Svr3> {
    pub cdsi: EnclaveEndpoint<'a, Cdsi>,
    pub svr2: EnclaveEndpoint<'a, SgxPreQuantum>,
    pub svr3: Svr3,
    pub chat_domain_config: DomainConfig,
}

impl<'a> Env<'a, Svr3Env<'a>> {
    /// Returns a static mapping from hostnames to [`LookupResult`]s.
    pub fn static_fallback(&self) -> HashMap<&'a str, LookupResult> {
        let Self {
            cdsi,
            svr2,
            svr3,
            chat_domain_config,
        } = self;
        HashMap::from([
            cdsi.domain_config.static_fallback(),
            svr2.domain_config.static_fallback(),
            svr3.sgx().domain_config.static_fallback(),
            svr3.nitro().domain_config.static_fallback(),
            svr3.tpm2snp().domain_config.static_fallback(),
            chat_domain_config.static_fallback(),
        ])
    }
}

pub struct Svr3Env<'a>(
    EnclaveEndpoint<'a, Sgx>,
    EnclaveEndpoint<'a, Nitro>,
    EnclaveEndpoint<'a, Tpm2Snp>,
);

impl<'a> Svr3Env<'a> {
    #[inline]
    pub const fn sgx(&self) -> &EnclaveEndpoint<'a, Sgx> {
        &self.0
    }

    #[inline]
    pub const fn nitro(&self) -> &EnclaveEndpoint<'a, Nitro> {
        &self.1
    }

    #[inline]
    pub const fn tpm2snp(&self) -> &EnclaveEndpoint<'a, Tpm2Snp> {
        &self.2
    }
}

pub const STAGING: Env<'static, Svr3Env> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT_STAGING,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI_STAGING,
        params: ENDPOINT_PARAMS_CDSI_STAGING,
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2_STAGING,
        params: ENDPOINT_PARAMS_SVR2_STAGING,
    },
    svr3: Svr3Env(
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_SGX_STAGING,
            params: ENDPOINT_PARAMS_SVR3_SGX_STAGING,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_NITRO_STAGING,
            params: ENDPOINT_PARAMS_SVR3_NITRO_STAGING,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_TPM2SNP_STAGING,
            params: ENDPOINT_PARAMS_SVR3_TPM2SNP_STAGING,
        },
    ),
};

pub const PROD: Env<'static, Svr3Env> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI,
        params: ENDPOINT_PARAMS_CDSI_PROD,
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2,
        params: ENDPOINT_PARAMS_SVR2_PROD,
    },
    svr3: Svr3Env(
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_SGX,
            params: ENDPOINT_PARAMS_SVR3_SGX_PROD,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_NITRO,
            params: ENDPOINT_PARAMS_SVR3_NITRO_PROD,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_TPM2SNP,
            params: ENDPOINT_PARAMS_SVR3_TPM2SNP_PROD,
        },
    ),
};

pub mod constants {
    pub const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use super::*;

    #[test_matrix([&DOMAIN_CONFIG_CHAT, &DOMAIN_CONFIG_CHAT_STAGING])]
    fn chat_has_confirmation_header(config: &DomainConfig) {
        assert_eq!(
            Some(TIMESTAMP_HEADER_NAME),
            config
                .connect
                .direct_connection_params()
                .connection_confirmation_header
                .as_ref()
                .map(|header| header.as_str())
        );
        for params in config.connect.connection_params_with_fallback() {
            assert_eq!(
                Some(TIMESTAMP_HEADER_NAME),
                params
                    .connection_confirmation_header
                    .as_ref()
                    .map(|header| header.as_str()),
                "{}",
                params.transport.sni,
            );
        }
    }

    #[test_matrix([&DOMAIN_CONFIG_CDSI, &DOMAIN_CONFIG_CDSI_STAGING])]
    fn cdsi_has_no_confirmation_header(config: &DomainConfig) {
        assert_eq!(
            None,
            config
                .connect
                .direct_connection_params()
                .connection_confirmation_header
                .as_ref()
                .map(|header| header.as_str())
        );
        for params in config.connect.connection_params_with_fallback() {
            assert_eq!(
                None,
                params
                    .connection_confirmation_header
                    .as_ref()
                    .map(|header| header.as_str()),
                "{}",
                params.transport.sni,
            );
        }
    }
}
