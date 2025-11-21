//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::iter;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::sync::Arc;

use boring_signal::ssl::SslVersion;
use const_str::{hex, ip_addr};
use http::HeaderValue;
use libsignal_keytrans::{DeploymentMode, PublicConfig, VerifyingKey, VerifyingKeys, VrfPublicKey};
use libsignal_net_infra::certs::RootCertificates;
use libsignal_net_infra::dns::lookup_result::LookupResult;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::{
    DirectTcpRouteProvider, DomainFrontConfig, DomainFrontRouteProvider, HttpVersion,
    HttpsProvider, TlsRouteProvider,
};
use libsignal_net_infra::{
    AsStaticHttpHeader, ConnectionParams, EnableDomainFronting, EnforceMinimumTls,
    OverrideNagleAlgorithm, RECOMMENDED_WS_CONFIG, RouteType, TransportConnectionParams,
};
use nonzero_ext::nonzero;
use rand::seq::SliceRandom;
use rand::{Rng, rng};

use crate::certs::{PROXY_G_ROOT_CERTIFICATES, SIGNAL_ROOT_CERTIFICATES};
use crate::chat::RECOMMENDED_CHAT_WS_CONFIG;
use crate::enclave::{Cdsi, EnclaveEndpoint, EndpointParams, MrEnclave, SvrSgx};

const DEFAULT_HTTPS_PORT: NonZeroU16 = nonzero!(443_u16);
pub const TIMESTAMP_HEADER_NAME: &str = "x-signal-timestamp";
pub(crate) const ALERT_HEADER_NAME: &str = "x-signal-alert";
pub(crate) const CONNECTION_INVALIDATED_CLOSE_CODE: u16 = 4401;
pub(crate) const CONNECTED_ELSEWHERE_CLOSE_CODE: u16 = 4409;

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
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
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
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
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
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
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
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
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
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
        confirmation_header_name: None,
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr2",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
    },
    ip_v4: &[
        ip_addr!(v4, "20.236.21.158"),
        ip_addr!(v4, "20.104.52.125"),
        ip_addr!(v4, "20.9.45.98"),
        ip_addr!(v4, "20.66.40.69"),
        ip_addr!(v4, "20.119.62.85"),
        ip_addr!(v4, "20.65.43.198"),
        ip_addr!(v4, "13.84.216.212"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2603:1030:20e:33::6"),
        ip_addr!(v6, "2603:1030:408:3::1d"),
        ip_addr!(v6, "2603:1030:b:2a::12"),
        ip_addr!(v6, "2603:1030:803:4::65"),
        ip_addr!(v6, "2a01:111:f100:3000::a83e:1208"),
        ip_addr!(v6, "2603:1030:c04:1e::31c"),
        ip_addr!(v6, "2603:1030:f00::17"),
    ],
};

const DOMAIN_CONFIG_SVR2_STAGING: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "svr2.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
        confirmation_header_name: None,
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr2-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
    },
    ip_v4: &[
        ip_addr!(v4, "104.43.134.192"),
        ip_addr!(v4, "20.253.229.239"),
        ip_addr!(v4, "157.55.188.67"),
        ip_addr!(v4, "20.127.86.118"),
        ip_addr!(v4, "20.186.175.196"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2603:1030:20e:31::20e"),
        ip_addr!(v6, "2603:1030:403:29::7f"),
        ip_addr!(v6, "2603:1030:b:2c::26"),
        ip_addr!(v6, "2603:1030:800:5::bfee:ab23"),
        ip_addr!(v6, "2603:1030:a04:16::3a"),
    ],
};

const DOMAIN_CONFIG_SVRB_STAGING: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "svrb.staging.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
        confirmation_header_name: None,
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svrb-staging",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
    },
    ip_v4: &[
        ip_addr!(v4, "20.45.59.200"),
        ip_addr!(v4, "132.196.9.248"),
        ip_addr!(v4, "52.225.216.56"),
        ip_addr!(v4, "20.66.46.240"),
        ip_addr!(v4, "172.178.57.240"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2a01:111:f100:2004::8975:6ea4"),
        ip_addr!(v6, "2603:1030:408:7::31"),
        ip_addr!(v6, "2603:1030:b:29::8f"),
        ip_addr!(v6, "2603:1030:800:5::bfee:ab24"),
        ip_addr!(v6, "2603:1030:a04:26::82"),
    ],
};

const DOMAIN_CONFIG_SVRB_PROD: DomainConfig = DomainConfig {
    connect: ConnectionConfig {
        hostname: "svrb.signal.org",
        port: DEFAULT_HTTPS_PORT,
        cert: SIGNAL_ROOT_CERTIFICATES,
        min_tls_version: Some(SslVersion::TLS1_3),
        http_version: Some(HttpVersion::Http1_1),
        confirmation_header_name: None,
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svrb",
            configs: [PROXY_CONFIG_F_PROD, PROXY_CONFIG_G],
        }),
    },
    ip_v4: &[
        ip_addr!(v4, "4.151.136.48"),
        ip_addr!(v4, "20.232.191.209"),
        ip_addr!(v4, "135.119.74.80"),
        ip_addr!(v4, "172.200.87.186"),
        ip_addr!(v4, "20.63.12.55"),
        ip_addr!(v4, "20.66.41.177"),
        ip_addr!(v4, "20.114.45.6"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2603:1030:20c:6::166"),
        ip_addr!(v6, "2603:1030:408:6::e5"),
        ip_addr!(v6, "2603:1030:7:5::22"),
        ip_addr!(v6, "2a01:111:f100:4001::4625:a047"),
        ip_addr!(v6, "2a01:111:f100:3000::a83e:14da"),
        ip_addr!(v6, "2603:1030:c02:5::632"),
        ip_addr!(v6, "2603:1030:f00:3::27"),
    ],
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
        "googlemail.com",
    ],
    certs: PROXY_G_ROOT_CERTIFICATES,
};

pub(crate) const ENDPOINT_PARAMS_CDSI_STAGING: EndpointParams<'static, Cdsi> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_STAGING),
    raft_config: (),
};

pub(crate) const ENDPOINT_PARAMS_SVR2_STAGING: EndpointParams<'static, SvrSgx> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_STAGING),
    raft_config: attest::constants::RAFT_CONFIG_SVR2_STAGING,
};

pub(crate) const ENDPOINT_PARAMS_SVRB_STAGING: EndpointParams<'static, SvrSgx> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVRB_STAGING),
    raft_config: attest::constants::RAFT_CONFIG_SVRB_STAGING,
};

pub(crate) const ENDPOINT_PARAMS_SVRB_PROD: EndpointParams<'static, SvrSgx> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVRB_PROD),
    raft_config: attest::constants::RAFT_CONFIG_SVRB_PROD,
};

pub(crate) const ENDPOINT_PARAMS_CDSI_PROD: EndpointParams<'static, Cdsi> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_PROD),
    raft_config: (),
};

pub(crate) const ENDPOINT_PARAMS_SVR2_PROD: EndpointParams<'static, SvrSgx> = EndpointParams {
    mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_PROD),
    raft_config: attest::constants::RAFT_CONFIG_SVR2_PROD,
};

pub(crate) const KEYTRANS_SIGNING_KEY_MATERIAL_STAGING: &[u8; 32] =
    &hex!("ac0de1fd7f33552bbeb6ebc12b9d4ea10bf5f025c45073d3fb5f5648955a749e");
pub(crate) const KEYTRANS_VRF_KEY_MATERIAL_STAGING: &[u8; 32] =
    &hex!("ec3a268237cf5c47115cf222405d5f90cc633ebe05caf82c0dd5acf9d341dadb");
pub(crate) const KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING: &[&[u8; 32]] = &[
    &hex!("1123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755"),
    &hex!("bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e"),
    &hex!("093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd636"),
];

pub(crate) const KEYTRANS_CONFIG_STAGING: KeyTransConfig = KeyTransConfig {
    signing_key_material: KEYTRANS_SIGNING_KEY_MATERIAL_STAGING,
    vrf_key_material: KEYTRANS_VRF_KEY_MATERIAL_STAGING,
    auditor_key_material: KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING,
};

pub(crate) const KEYTRANS_SIGNING_KEY_MATERIAL_PROD: &[u8; 32] =
    &hex!("a3973067984382cfa89ec26d7cc176680aefe92b3d2eba85159dad0b8354b622");
pub(crate) const KEYTRANS_VRF_KEY_MATERIAL_PROD: &[u8; 32] =
    &hex!("3849cf116c7bc9aef5f13f0c61a7c246e5bade4eb7e1c7b0efcacdd8c1e6a6ff");
pub(crate) const KEYTRANS_AUDITOR_KEY_MATERIAL_PROD: &[&[u8; 32]] = &[
    &hex!("2d973608e909a09e12cbdbd21ad58775fd72fe1034a5a079f26541d5764ce17f"),
    &hex!("2f217a86cd2dbc95d46a84420942a95877b3723f634bc64bb9e406796df746ef"),
    &hex!("7fe5d91de235188486d8fb836a6da37e625e2b10eb6d144185b9364cc83cbbb6"),
];

pub(crate) const KEYTRANS_CONFIG_PROD: KeyTransConfig = KeyTransConfig {
    signing_key_material: KEYTRANS_SIGNING_KEY_MATERIAL_PROD,
    vrf_key_material: KEYTRANS_VRF_KEY_MATERIAL_PROD,
    auditor_key_material: KEYTRANS_AUDITOR_KEY_MATERIAL_PROD,
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
    /// Which minimum version of TLS to require when connecting to the resource.
    pub min_tls_version: Option<SslVersion>,
    /// Which version of HTTP to expect when connecting to the resource.
    ///
    /// This may be `None` for a non-HTTP resource.
    pub http_version: Option<HttpVersion>,
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

#[derive(Clone)]
pub struct KeyTransConfig {
    pub signing_key_material: &'static [u8; 32],
    pub vrf_key_material: &'static [u8; 32],
    pub auditor_key_material: &'static [&'static [u8; 32]],
}

pub enum StaticIpOrder<'a, R> {
    Hardcoded,
    Shuffled(&'a mut R),
}

impl StaticIpOrder<'_, rand::rngs::ThreadRng> {
    /// A convenience alias for [`Self::Hardcoded`] with a fixed RNG type.
    pub const HARDCODED: Self = Self::Hardcoded;
}

impl<'a, R> StaticIpOrder<'a, R> {
    /// Borrow `self` without consuming it.
    ///
    /// Makes up for `&mut` not being `Clone`, cf [`Option::as_mut`].
    fn as_mut<'b>(&'b mut self) -> StaticIpOrder<'b, R> {
        match self {
            StaticIpOrder::Hardcoded => StaticIpOrder::Hardcoded,
            StaticIpOrder::Shuffled(rng) => StaticIpOrder::Shuffled(rng),
        }
    }
}

impl DomainConfig {
    pub fn static_fallback(
        &self,
        rng: StaticIpOrder<'_, impl Rng>,
    ) -> (&'static str, LookupResult) {
        let mut ip_v4 = self.ip_v4.to_vec();
        let mut ip_v6 = self.ip_v6.to_vec();
        if let StaticIpOrder::Shuffled(rng) = rng {
            ip_v4.shuffle(rng);
            ip_v6.shuffle(rng);
        }
        (self.connect.hostname, LookupResult::new(ip_v4, ip_v6))
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
                path_prefix: None,
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
            let mut rng = rng();
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
        override_nagle_algorithm: OverrideNagleAlgorithm,
    ) -> HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>> {
        let Self {
            hostname,
            port,
            cert,
            min_tls_version,
            http_version,
            confirmation_header_name: _,
            proxy,
        } = self;
        let domain_front_configs = proxy
            .as_ref()
            .filter(|_proxy| !matches!(enable_domain_fronting, EnableDomainFronting::No))
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
                            return_routes_with_all_snis: matches!(
                                enable_domain_fronting,
                                EnableDomainFronting::AllDomains
                            ),
                        }
                    };
                    configs.iter().map(make_proxy_config)
                },
            )
            .into_iter()
            .flatten()
            .collect();

        let hostname = Arc::<str>::from(*hostname);

        let direct_tcp_provider =
            DirectTcpRouteProvider::new(Arc::clone(&hostname), *port, override_nagle_algorithm);

        HttpsProvider::new(
            Arc::clone(&hostname),
            http_version.expect("must have an HTTP version to connect to an HTTP resource"),
            DomainFrontRouteProvider::new(
                HttpVersion::Http1_1,
                domain_front_configs,
                override_nagle_algorithm,
            ),
            TlsRouteProvider::new(
                cert.clone(),
                *min_tls_version,
                Host::Domain(Arc::clone(&hostname)),
                direct_tcp_provider,
            ),
        )
    }

    pub fn route_provider_with_options(
        &self,
        enable_domain_fronting: EnableDomainFronting,
        enforce_minimum_tls: EnforceMinimumTls,
        override_nagle_algorithm: OverrideNagleAlgorithm,
    ) -> HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>> {
        match enforce_minimum_tls {
            EnforceMinimumTls::Yes => {
                self.route_provider(enable_domain_fronting, override_nagle_algorithm)
            }
            EnforceMinimumTls::No => self
                .config_with_permissive_min_tls_version()
                .route_provider(enable_domain_fronting, override_nagle_algorithm),
        }
    }

    pub fn config_with_permissive_min_tls_version(&self) -> Self {
        let mut permissive_config = self.clone();
        permissive_config.min_tls_version = None;
        permissive_config
    }
}

#[derive(Clone)]
pub struct UserAgent(HeaderValue);

impl UserAgent {
    pub fn with_libsignal_version(user_agent: &str) -> Self {
        let with_lib_version = format!("{} libsignal/{}", user_agent, libsignal_core::VERSION);
        Self(HeaderValue::try_from(&with_lib_version).expect("valid header string"))
    }
}

impl AsStaticHttpHeader for UserAgent {
    const HEADER_NAME: http::HeaderName = http::header::USER_AGENT;

    fn header_value(&self) -> HeaderValue {
        self.0.clone()
    }
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
    pub fn shuffled_connection_params<R>(
        &self,
        proxy_path: &'static str,
        confirmation_header_name: Option<&'static str>,
        rng: &mut R,
    ) -> impl Iterator<Item = ConnectionParams> + use<R>
    where
        R: Rng,
    {
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
                path_prefix: Some(proxy_path),
                connection_confirmation_header: confirmation_header_name
                    .map(http::HeaderName::from_static),
            }
        })
    }

    #[cfg(feature = "test-util")]
    pub fn route_type(&self) -> RouteType {
        self.route_type
    }

    #[cfg(feature = "test-util")]
    pub fn hostnames(&self) -> &[&'static str] {
        self.sni_list
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
        let auditor_keys = auditor_key_material
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("valid auditor key material"));
        let vrf_key = VrfPublicKey::try_from(*vrf_key_material).expect("valid VRF key material");
        Self {
            mode: DeploymentMode::ThirdPartyAuditing(VerifyingKeys::from(auditor_keys)),
            signature_key,
            vrf_key,
        }
    }
}

const SVRB_ENV_MAX_CURRENT: usize = 3;
const SVRB_ENV_MAX_PREVIOUS: usize = 3;

pub struct SvrBEnv<'a> {
    // There may be differing numbers of current/previous endpoints in staging vs prod,
    // so rather than store a fixed-sized array of current/previous, we store
    // a max-sized list of Options, which are often None but can be set.
    // Thus, if staging has 2 and prod has 1, they can set [Some(foo), Some(bar), None] and
    // [Some(baz), None, None] respectively.
    current: [Option<EnclaveEndpoint<'a, SvrSgx>>; SVRB_ENV_MAX_CURRENT],
    previous: [Option<EnclaveEndpoint<'a, SvrSgx>>; SVRB_ENV_MAX_PREVIOUS],
}

impl<'a> SvrBEnv<'a> {
    pub const fn new(
        current: [Option<EnclaveEndpoint<'a, SvrSgx>>; SVRB_ENV_MAX_CURRENT],
        previous: [Option<EnclaveEndpoint<'a, SvrSgx>>; SVRB_ENV_MAX_PREVIOUS],
    ) -> Self {
        Self { current, previous }
    }

    pub fn current(&self) -> impl std::iter::Iterator<Item = &EnclaveEndpoint<'a, SvrSgx>> {
        self.current.iter().filter_map(|a| a.as_ref())
    }

    pub fn previous(&self) -> impl std::iter::Iterator<Item = &EnclaveEndpoint<'a, SvrSgx>> {
        self.previous.iter().filter_map(|a| a.as_ref())
    }

    pub fn current_and_previous(
        &self,
    ) -> impl std::iter::Iterator<Item = &EnclaveEndpoint<'a, SvrSgx>> {
        self.current().chain(self.previous())
    }
}

pub struct Env<'a> {
    pub cdsi: EnclaveEndpoint<'a, Cdsi>,
    pub svr2: EnclaveEndpoint<'a, SvrSgx>,
    pub svr_b: SvrBEnv<'a>,
    pub chat_domain_config: DomainConfig,
    pub chat_ws_config: crate::chat::ws::Config,
    pub keytrans_config: KeyTransConfig,
}

impl<'a> Env<'a> {
    /// Returns a static mapping from hostnames to [`LookupResult`]s.
    ///
    /// If an RNG is provided, the static IPs are shuffled in the resulting map.
    pub fn static_fallback(
        &self,
        mut rng: StaticIpOrder<'_, impl Rng>,
    ) -> HashMap<&'a str, LookupResult> {
        let Self {
            cdsi,
            svr2,
            chat_domain_config,
            svr_b,
            chat_ws_config: _,
            keytrans_config: _,
        } = self;

        let mut result = HashMap::from_iter([
            cdsi.domain_config.static_fallback(rng.as_mut()),
            svr2.domain_config.static_fallback(rng.as_mut()),
            chat_domain_config.static_fallback(rng.as_mut()),
        ]);
        result.extend(
            svr_b.current_and_previous().map(|enclave_endpoint| {
                enclave_endpoint.domain_config.static_fallback(rng.as_mut())
            }),
        );
        result
    }
}

pub const STAGING: Env<'static> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT_STAGING,
    chat_ws_config: RECOMMENDED_CHAT_WS_CONFIG,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI_STAGING,
        ws_config: RECOMMENDED_WS_CONFIG,
        params: ENDPOINT_PARAMS_CDSI_STAGING,
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2_STAGING,
        ws_config: RECOMMENDED_WS_CONFIG,
        params: ENDPOINT_PARAMS_SVR2_STAGING,
    },
    svr_b: SvrBEnv {
        current: [
            Some(EnclaveEndpoint {
                domain_config: DOMAIN_CONFIG_SVRB_STAGING,
                ws_config: RECOMMENDED_WS_CONFIG,
                params: ENDPOINT_PARAMS_SVRB_STAGING,
            }),
            None,
            None,
        ],
        previous: [None, None, None],
    },
    keytrans_config: KEYTRANS_CONFIG_STAGING,
};

pub const PROD: Env<'static> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT,
    chat_ws_config: RECOMMENDED_CHAT_WS_CONFIG,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI,
        ws_config: RECOMMENDED_WS_CONFIG,
        params: ENDPOINT_PARAMS_CDSI_PROD,
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2,
        ws_config: RECOMMENDED_WS_CONFIG,
        params: ENDPOINT_PARAMS_SVR2_PROD,
    },
    svr_b: SvrBEnv {
        current: [
            Some(EnclaveEndpoint {
                domain_config: DOMAIN_CONFIG_SVRB_PROD,
                ws_config: RECOMMENDED_WS_CONFIG,
                params: ENDPOINT_PARAMS_SVRB_PROD,
            }),
            None,
            None,
        ],
        previous: [None, None, None],
    },
    keytrans_config: KEYTRANS_CONFIG_PROD,
};

pub mod constants {
    pub const CHAT_WEBSOCKET_PATH: &str = "/v1/websocket/";
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::time::Duration;

    use itertools::Itertools as _;
    use libsignal_net_infra::Alpn;
    use libsignal_net_infra::dns::build_custom_resolver_cloudflare_doh;
    use libsignal_net_infra::dns::dns_lookup::DnsLookupRequest;
    use libsignal_net_infra::route::testutils::FakeContext;
    use libsignal_net_infra::route::{
        HttpRouteFragment, HttpsTlsRoute, RouteProvider as _, TcpRoute, TlsRoute, TlsRouteFragment,
        UnresolvedHost,
    };
    use libsignal_net_infra::utils::no_network_change_events;
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

    #[test_matrix(
        [true, false],
        [
            OverrideNagleAlgorithm::UseSystemDefault,
            OverrideNagleAlgorithm::OverrideToOff
        ]
    )]
    fn connect_config_routes_respect_route_provider_settings(
        enable_domain_fronting: bool,
        override_nagle_algorithm: OverrideNagleAlgorithm,
    ) {
        const PORT: NonZeroU16 = nonzero!(123u16);
        const CONNECT_CONFIG: ConnectionConfig = ConnectionConfig {
            hostname: "host",
            port: PORT,
            cert: RootCertificates::Native,
            min_tls_version: Some(SslVersion::TLS1_2),
            http_version: Some(HttpVersion::Http1_1),
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
        let route_provider = CONNECT_CONFIG.route_provider(
            if enable_domain_fronting {
                EnableDomainFronting::OneDomainPerProxy
            } else {
                EnableDomainFronting::No
            },
            override_nagle_algorithm,
        );
        let routes = route_provider.routes(&FakeContext::new()).collect_vec();

        let expected_direct_route = HttpsTlsRoute {
            fragment: HttpRouteFragment {
                host_header: "host".into(),
                path_prefix: "".into(),
                http_version: Some(HttpVersion::Http1_1),
                front_name: None,
            },
            inner: TlsRoute {
                fragment: TlsRouteFragment {
                    root_certs: RootCertificates::Native,
                    sni: Host::Domain("host".into()),
                    alpn: Some(Alpn::Http1_1),
                    min_protocol_version: Some(SslVersion::TLS1_2),
                },
                inner: TcpRoute {
                    address: UnresolvedHost::from(Arc::from("host")),
                    port: PORT,
                    override_nagle_algorithm,
                },
            },
        };

        assert!(routes
            .iter()
            .all(|route| route.inner.inner.override_nagle_algorithm == override_nagle_algorithm));

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
        let resolver = build_custom_resolver_cloudflare_doh(
            &no_network_change_events(),
            // We want to check responses for IPv4 and IPv6 so don't time out if
            // one of them takes too long. We'll still be subject to the overall
            // lookup timeout regardless.
            Duration::MAX,
        );

        let (hostname, static_hardcoded_ips) = config.static_fallback(StaticIpOrder::HARDCODED);

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
            "Resolved IP addresses do not match static ones for {hostname}"
        );
    }
}
