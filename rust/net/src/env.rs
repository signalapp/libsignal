//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::iter;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use const_str::ip_addr;
use nonzero_ext::nonzero;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

use crate::enclave::{Cdsi, EnclaveEndpoint, MrEnclave, Nitro, Sgx, Tpm2Snp};
use crate::infra::certs::RootCertificates;
use crate::infra::dns::lookup_result::LookupResult;
use crate::infra::{
    ConnectionParams, DnsSource, HttpRequestDecorator, HttpRequestDecoratorSeq, RouteType,
};

const DEFAULT_HTTPS_PORT: NonZeroU16 = nonzero!(443_u16);

const DOMAIN_CONFIG_CHAT: DomainConfig = DomainConfig {
    hostname: "chat.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[
        ip_addr!(v4, "76.223.92.165"),
        ip_addr!(v4, "13.248.212.111"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2600:9000:a507:ab6d:4ce3:2f58:25d7:9cbf"),
        ip_addr!(v6, "2600:9000:a61f:527c:d5eb:a431:5239:3232"),
    ],
    cert: RootCertificates::Signal,
    proxy_path: "/service",
};

const DOMAIN_CONFIG_CHAT_STAGING: DomainConfig = DomainConfig {
    hostname: "chat.staging.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[
        ip_addr!(v4, "76.223.72.142"),
        ip_addr!(v4, "13.248.206.115"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2600:9000:a507:ab6d:7b25:2580:8bd6:3b93"),
        ip_addr!(v6, "2600:9000:a61f:527c:2215:cd9:bac6:a2f8"),
    ],
    cert: RootCertificates::Signal,
    proxy_path: "/service-staging",
};

const DOMAIN_CONFIG_CDSI: DomainConfig = DomainConfig {
    hostname: "cdsi.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "40.122.45.194")],
    ip_v6: &[ip_addr!(v6, "2603:1030:7::1")],
    cert: RootCertificates::Signal,
    proxy_path: "/cdsi",
};

const DOMAIN_CONFIG_CDSI_STAGING: DomainConfig = DomainConfig {
    hostname: "cdsi.staging.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "104.43.162.137")],
    ip_v6: &[ip_addr!(v6, "2603:1030:7::732")],
    cert: RootCertificates::Signal,
    proxy_path: "/cdsi-staging",
};

const DOMAIN_CONFIG_SVR2: DomainConfig = DomainConfig {
    hostname: "svr2.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "20.66.40.69")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr2",
};

const DOMAIN_CONFIG_SVR2_STAGING: DomainConfig = DomainConfig {
    hostname: "svr2.staging.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "20.253.229.239")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr2-staging",
};

const DOMAIN_CONFIG_SVR3_SGX: DomainConfig = DomainConfig {
    hostname: "backend1.svr3.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "40.112.138.96")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr3-sgx",
};

const DOMAIN_CONFIG_SVR3_SGX_STAGING: DomainConfig = DomainConfig {
    hostname: "backend1.svr3.staging.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "13.88.63.29")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr3-sgx-staging",
};

const DOMAIN_CONFIG_SVR3_NITRO: DomainConfig = DomainConfig {
    hostname: "backend2.svr3.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "75.2.91.98")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr3-nitro",
};

const DOMAIN_CONFIG_SVR3_NITRO_STAGING: DomainConfig = DomainConfig {
    hostname: "backend2.svr3.staging.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "75.2.86.85"), ip_addr!(v4, "99.83.239.137")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr3-nitro-staging",
};

pub const DOMAIN_CONFIG_SVR3_TPM2SNP: DomainConfig = DomainConfig {
    hostname: "backend3.svr3.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "34.144.241.251")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr3-tpm2snp",
};

pub const DOMAIN_CONFIG_SVR3_TPM2SNP_STAGING: DomainConfig = DomainConfig {
    hostname: "backend3.svr3.staging.signal.org",
    port: DEFAULT_HTTPS_PORT,
    ip_v4: &[ip_addr!(v4, "13.88.30.76")],
    ip_v6: &[],
    cert: RootCertificates::Signal,
    proxy_path: "/svr3-tpm2snp-staging",
};

const PROXY_CONFIG_F: ProxyConfig = ProxyConfig {
    route_type: RouteType::ProxyF,
    hostname: "reflector-signal.global.ssl.fastly.net",
    sni_list: &[
        "github.githubassets.com",
        "pinterest.com",
        "www.redditstatic.com",
    ],
};

const PROXY_CONFIG_G: ProxyConfig = ProxyConfig {
    route_type: RouteType::ProxyG,
    hostname: "reflector-nrgwuv7kwq-uc.a.run.app",
    sni_list: &[
        "www.google.com",
        "android.clients.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "inbox.google.com",
    ],
};

#[derive(Clone)]
pub struct DomainConfig {
    pub hostname: &'static str,
    pub port: NonZeroU16,
    pub proxy_path: &'static str,
    pub ip_v4: &'static [Ipv4Addr],
    pub ip_v6: &'static [Ipv6Addr],
    pub cert: RootCertificates,
}

impl DomainConfig {
    pub fn static_fallback(&self) -> (&'static str, LookupResult) {
        (
            self.hostname,
            LookupResult::new(DnsSource::Static, self.ip_v4.into(), self.ip_v6.into()),
        )
    }

    pub fn connection_params(&self) -> ConnectionParams {
        ConnectionParams::new(
            RouteType::Direct,
            self.hostname,
            self.hostname,
            self.port,
            HttpRequestDecoratorSeq::default(),
            self.cert.clone(),
        )
    }

    pub fn connection_params_with_fallback(&self) -> Vec<ConnectionParams> {
        let direct = self.connection_params();
        let rng = thread_rng();
        let shuffled_g_params =
            PROXY_CONFIG_G.shuffled_connection_params(self.proxy_path, rng.clone());
        let shuffled_f_params = PROXY_CONFIG_F.shuffled_connection_params(self.proxy_path, rng);
        let proxy_params = itertools::interleave(shuffled_g_params, shuffled_f_params);
        iter::once(direct).chain(proxy_params).collect()
    }
}

pub fn add_user_agent_header(
    mut connection_params_list: Vec<ConnectionParams>,
    user_agent: &str,
) -> Vec<ConnectionParams> {
    let with_lib_version = format!("{} libsignal/{}", user_agent, libsignal_core::VERSION);
    connection_params_list.iter_mut().for_each(|cp| {
        cp.http_request_decorator.add(HttpRequestDecorator::Header(
            http::header::USER_AGENT,
            http::header::HeaderValue::try_from(&with_lib_version).expect("valid header string"),
        ));
    });
    connection_params_list
}

pub struct ProxyConfig {
    route_type: RouteType,
    hostname: &'static str,
    sni_list: &'static [&'static str],
}

impl ProxyConfig {
    pub fn shuffled_connection_params<'a>(
        &'a self,
        proxy_path: &'static str,
        mut rng: impl Rng,
    ) -> impl Iterator<Item = ConnectionParams> + 'a {
        let mut sni_list = self.sni_list.to_vec();
        sni_list.shuffle(&mut rng);
        sni_list.into_iter().map(move |sni| {
            ConnectionParams::new(
                self.route_type,
                sni,
                self.hostname,
                nonzero!(443u16),
                HttpRequestDecorator::PathPrefix(proxy_path).into(),
                RootCertificates::Native,
            )
        })
    }
}

pub struct Env<'a, Svr3> {
    pub cdsi: EnclaveEndpoint<'a, Cdsi>,
    pub svr2: EnclaveEndpoint<'a, Sgx>,
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
    pub fn sgx(&self) -> &EnclaveEndpoint<'a, Sgx> {
        &self.0
    }

    #[inline]
    pub fn nitro(&self) -> &EnclaveEndpoint<'a, Nitro> {
        &self.1
    }

    #[inline]
    pub fn tpm2snp(&self) -> &EnclaveEndpoint<'a, Tpm2Snp> {
        &self.2
    }
}

pub const STAGING: Env<'static, Svr3Env> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT_STAGING,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI_STAGING,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_STAGING),
        raft_config: (),
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2_STAGING,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_STAGING),
        raft_config: attest::constants::RAFT_CONFIG_SVR2_STAGING,
    },
    svr3: Svr3Env(
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_SGX_STAGING,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_SGX_STAGING),
            raft_config: attest::constants::RAFT_CONFIG_SVR3_SGX_STAGING,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_NITRO_STAGING,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_NITRO_STAGING),
            raft_config: attest::constants::RAFT_CONFIG_SVR3_NITRO_STAGING,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_TPM2SNP_STAGING,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_TPM2SNP_STAGING),
            raft_config: attest::constants::RAFT_CONFIG_SVR3_TPM2SNP_STAGING,
        },
    ),
};

pub const PROD: Env<'static, Svr3Env> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_PROD),
        raft_config: (),
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_PROD),
        raft_config: attest::constants::RAFT_CONFIG_SVR2_PROD,
    },
    svr3: Svr3Env(
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_SGX,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_SGX_PROD),
            raft_config: attest::constants::RAFT_CONFIG_SVR3_SGX_PROD,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_NITRO,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_NITRO_PROD),
            raft_config: attest::constants::RAFT_CONFIG_SVR3_NITRO_PROD,
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_TPM2SNP,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_TPM2SNP_PROD),
            raft_config: attest::constants::RAFT_CONFIG_SVR3_TPM2SNP_PROD,
        },
    ),
};

pub mod constants {
    pub const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}
