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
use hex_literal::hex;
use http::HeaderValue;
use libsignal_keytrans::{DeploymentMode, PublicConfig, VerifyingKey, VrfPublicKey};
use libsignal_net_infra::certs::RootCertificates;
use libsignal_net_infra::dns::lookup_result::LookupResult;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::{
    DirectTcpRouteProvider, DomainFrontConfig, DomainFrontRouteProvider, HttpVersion,
    HttpsProvider, TlsRouteProvider,
};
use libsignal_net_infra::{
    AsHttpHeader, ConnectionParams, DnsSource, EnableDomainFronting, HttpRequestDecorator,
    HttpRequestDecoratorSeq, RouteType, TransportConnectionParams,
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/service",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/service-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
    },
};

const DOMAIN_CONFIG_CDSI: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "cdsi.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        confirmation_header_name: None,
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/cdsi",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/cdsi-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr2",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr2-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr3-sgx",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr3-sgx-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr3-nitro",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr3-nitro-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr3-tpm2snp",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
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
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr3-tpm2snp-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
    },
    ip_v4: &[ip_addr!(v4, "13.88.30.76")],
    ip_v6: &[],
};

pub const PROXY_CONFIG_F_PROD: ProxyConfig = ProxyConfig {
    route_type: RouteType::ProxyF,
    http_host: "reflector-signal.global.ssl.fastly.net",
    sni_list: &[
        "github.githubassets.com",
        "pinterest.com",
        "www.redditstatic.com",
    ],
    certs: RootCertificates::Native,
};

pub const PROXY_CONFIG_F_STAGING: ProxyConfig = ProxyConfig {
    route_type: RouteType::ProxyF,
    http_host: "reflector-staging-signal.global.ssl.fastly.net",
    sni_list: &[
        "github.githubassets.com",
        "pinterest.com",
        "www.redditstatic.com",
    ],
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

pub(crate) const KEYTRANS_SIGNING_KEY_MATERIAL_STAGING: &[u8; 32] =
    &hex!("ac0de1fd7f33552bbeb6ebc12b9d4ea10bf5f025c45073d3fb5f5648955a749e");
pub(crate) const KEYTRANS_VRF_KEY_MATERIAL_STAGING: &[u8; 32] =
    &hex!("ec3a268237cf5c47115cf222405d5f90cc633ebe05caf82c0dd5acf9d341dadb");
pub(crate) const KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING: &[u8; 32] =
    &hex!("1123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755");

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
    pub proxy: Option<ConnectionProxyConfig>,
}

#[derive(Clone)]
pub struct ConnectionProxyConfig {
    /// A path prefix to prepend to any requests sent through the proxy.
    pub path_prefix: &'static str,
    /// The addresses for the proxies.
    pub configs: [ProxyConfig; 2],
}

pub struct KeyTransConfig {
    pub signing_key_material: &'static [u8; 32],
    pub vrf_key_material: &'static [u8; 32],
    pub auditor_key_material: &'static [u8; 32],
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
        if let Some(proxy) = &self.proxy {
            let mut rng = thread_rng();
            let [params_a, params_b] = proxy.configs.each_ref().map(|config| {
                config.shuffled_connection_params(
                    proxy.path_prefix,
                    self.confirmation_header_name,
                    &mut rng,
                )
            });

            let proxy_params = itertools::interleave(params_a, params_b);
            iter::once(direct).chain(proxy_params).collect()
        } else {
            iter::once(direct).collect()
        }
    }

    pub fn route_provider(
        &self,
        enable_domain_fronting: EnableDomainFronting,
    ) -> HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>> {
        let Self {
            hostname,
            port,
            cert,
            confirmation_header_name: _,
            proxy,
        } = self;
        let domain_front_configs = proxy
            .as_ref()
            .and_then(|proxy| enable_domain_fronting.0.then_some(proxy))
            .map(
                |ConnectionProxyConfig {
                     path_prefix,
                     configs,
                 }| {
                    let fronting_path_prefix = Arc::from(*path_prefix);
                    let make_proxy_config = move |config: &ProxyConfig| {
                        let ProxyConfig {
                            route_type,
                            http_host,
                            sni_list,
                            certs,
                        } = config;
                        DomainFrontConfig {
                            root_certs: certs.clone(),
                            http_host: (*http_host).into(),
                            sni_list: sni_list.iter().map(|sni| (*sni).into()).collect(),
                            path_prefix: Arc::clone(&fronting_path_prefix),
                            front_name: route_type.into(),
                            return_routes_with_all_snis: false,
                        }
                    };
                    configs.iter().map(make_proxy_config)
                },
            )
            .into_iter()
            .flatten()
            .collect();

        let hostname = Arc::<str>::from(*hostname);

        HttpsProvider::new(
            Arc::clone(&hostname),
            HttpVersion::Http1_1,
            DomainFrontRouteProvider::new(HttpVersion::Http1_1, domain_front_configs),
            TlsRouteProvider::new(
                cert.clone(),
                Host::Domain(Arc::clone(&hostname)),
                DirectTcpRouteProvider::new(hostname, *port),
            ),
        )
    }
}

pub struct UserAgent(HeaderValue);

impl UserAgent {
    pub fn with_libsignal_version(user_agent: &str) -> Self {
        let with_lib_version = format!("{} libsignal/{}", user_agent, libsignal_core::VERSION);
        Self(HeaderValue::try_from(&with_lib_version).expect("valid header string"))
    }
}

impl AsHttpHeader for UserAgent {
    const HEADER_NAME: http::HeaderName = http::header::USER_AGENT;

    fn header_value(&self) -> HeaderValue {
        self.0.clone()
    }
}

pub fn add_user_agent_header(
    mut connection_params_list: Vec<ConnectionParams>,
    agent: &UserAgent,
) -> Vec<ConnectionParams> {
    let (name, value) = agent.as_header();
    connection_params_list.iter_mut().for_each(|cp| {
        cp.http_request_decorator
            .add(HttpRequestDecorator::header(name.clone(), value.clone()));
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

    #[cfg(feature = "test-util")]
    pub fn hostnames(&self) -> impl Iterator<Item = &'static str> {
        self.sni_list.iter().copied()
    }
}

impl From<KeyTransConfig> for PublicConfig {
    fn from(src: KeyTransConfig) -> Self {
        let KeyTransConfig {
            signing_key_material,
            vrf_key_material,
            auditor_key_material,
        } = src;
        let signature_key =
            VerifyingKey::from_bytes(signing_key_material).expect("valid signing key material");
        let auditor_key =
            VerifyingKey::from_bytes(auditor_key_material).expect("valid auditor key material");
        let vrf_key = VrfPublicKey::try_from(*vrf_key_material).expect("valid VRF key material");
        Self {
            mode: DeploymentMode::ThirdPartyAuditing(auditor_key),
            signature_key,
            vrf_key,
        }
    }
}

pub struct Env<'a, Svr3> {
    pub cdsi: EnclaveEndpoint<'a, Cdsi>,
    pub svr2: EnclaveEndpoint<'a, SgxPreQuantum>,
    pub svr3: Svr3,
    pub chat_domain_config: DomainConfig,
    // TODO: make non-optional when the public endpoints are up
    pub keytrans_config: Option<KeyTransConfig>,
}

impl<'a> Env<'a, Svr3Env<'a>> {
    /// Returns a static mapping from hostnames to [`LookupResult`]s.
    pub fn static_fallback(&self) -> HashMap<&'a str, LookupResult> {
        let Self {
            cdsi,
            svr2,
            svr3,
            chat_domain_config,
            ..
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
    pub const fn new(
        sgx: EnclaveEndpoint<'a, Sgx>,
        nitro: EnclaveEndpoint<'a, Nitro>,
        tpm2snp: EnclaveEndpoint<'a, Tpm2Snp>,
    ) -> Self {
        Self(sgx, nitro, tpm2snp)
    }

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
    keytrans_config: Some(KeyTransConfig {
        signing_key_material: KEYTRANS_SIGNING_KEY_MATERIAL_STAGING,
        vrf_key_material: KEYTRANS_VRF_KEY_MATERIAL_STAGING,
        auditor_key_material: KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING,
    }),
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
    keytrans_config: None,
};

pub mod constants {
    pub const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use itertools::Itertools as _;
    use libsignal_net_infra::dns::build_custom_resolver_cloudflare_doh;
    use libsignal_net_infra::dns::dns_lookup::DnsLookupRequest;
    use libsignal_net_infra::route::testutils::FakeContext;
    use libsignal_net_infra::route::{
        HttpRouteFragment, HttpsTlsRoute, RouteProvider as _, TcpRoute, TlsRoute, TlsRouteFragment,
        UnresolvedHost,
    };
    use libsignal_net_infra::utils::ObservableEvent;
    use libsignal_net_infra::Alpn;
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

    #[test_matrix([true, false])]
    fn connect_config_routes_enable_domain_fronting(enable_domain_fronting: bool) {
        const PORT: NonZeroU16 = nonzero!(123u16);
        const CONNECT_CONFIG: ConnectionConfig = ConnectionConfig {
            hostname: "host",
            port: PORT,
            cert: RootCertificates::Native,
            confirmation_header_name: None,
            proxy: Some(ConnectionProxyConfig {
                path_prefix: "proxy-prefix",
                configs: [
                    ProxyConfig {
                        route_type: RouteType::ProxyF,
                        http_host: "proxy-host-1",
                        sni_list: &["sni-1-a", "sni-1-b"],
                        certs: RootCertificates::Native,
                    },
                    ProxyConfig {
                        route_type: RouteType::ProxyF,
                        http_host: "proxy-host0",
                        sni_list: &["sni-2-a", "sni-2-b"],
                        certs: RootCertificates::Native,
                    },
                ],
            }),
        };
        let route_provider =
            CONNECT_CONFIG.route_provider(EnableDomainFronting(enable_domain_fronting));
        let routes = route_provider.routes(&FakeContext::new()).collect_vec();

        let expected_direct_route = HttpsTlsRoute {
            fragment: HttpRouteFragment {
                host_header: "host".into(),
                path_prefix: "".into(),
                front_name: None,
            },
            inner: TlsRoute {
                fragment: TlsRouteFragment {
                    root_certs: RootCertificates::Native,
                    sni: Host::Domain("host".into()),
                    alpn: Some(Alpn::Http1_1),
                },
                inner: TcpRoute {
                    address: UnresolvedHost::from(Arc::from("host")),
                    port: PORT,
                },
            },
        };

        if enable_domain_fronting {
            assert_eq!(routes.first(), Some(&expected_direct_route));
            assert_eq!(routes.len(), 3, "{routes:?}");
        } else {
            assert_eq!(routes, [expected_direct_route]);
        };
    }

    #[tokio::test]
    #[test_matrix([&DOMAIN_CONFIG_CHAT, &DOMAIN_CONFIG_CHAT_STAGING, &DOMAIN_CONFIG_CDSI, &DOMAIN_CONFIG_CDSI_STAGING])]
    async fn live_resolve_eq_static_resolution(config: &DomainConfig) {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running test with network activity is not enabled");
            return;
        }

        // The point of this test isn't to test the resolver, but to use it to test something else.
        // So, I directly access the raw CustomDnsResolver::resolve method.
        // Other usages should use the higher level DnsResolver::lookup instead.
        let resolver = build_custom_resolver_cloudflare_doh(&ObservableEvent::new());

        let (hostname, static_hardcoded_ips) = config.static_fallback();

        let resolved_ips: Vec<_> = resolver
            .resolve(DnsLookupRequest {
                hostname: Arc::from(hostname),
                ipv6_enabled: true,
            })
            .await
            .unwrap_or_else(|_| panic!("Unable to resolve {hostname}"))
            .into_iter()
            .collect();

        let resolved_set = HashSet::<_>::from_iter(resolved_ips);
        let static_set = HashSet::<_>::from_iter(static_hardcoded_ips);

        assert_eq!(
            resolved_set, static_set,
            "Resolved IP addresses do not match static ones for {}",
            hostname
        );
    }
}
