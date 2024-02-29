//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use const_str::ip_addr;
use std::collections::HashMap;
use std::iter;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

use crate::enclave::{Cdsi, EnclaveEndpoint, MrEnclave, Nitro, Sgx};
use crate::infra::certs::RootCertificates;
use crate::infra::dns::{DnsResolver, LookupResult};
use crate::infra::{ConnectionParams, HttpRequestDecorator, HttpRequestDecoratorSeq};

pub(crate) const WS_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const WS_MAX_IDLE_TIME: Duration = Duration::from_secs(15);
pub(crate) const WS_MAX_CONNECTION_TIME: Duration = Duration::from_secs(2);

pub const DOMAIN_CONFIG_CHAT: DomainConfig = DomainConfig {
    hostname: "chat.signal.org",
    ip_v4: &[
        ip_addr!(v4, "76.223.92.165"),
        ip_addr!(v4, "13.248.212.111"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2600:9000:a507:ab6d:4ce3:2f58:25d7:9cbf"),
        ip_addr!(v6, "2600:9000:a61f:527c:d5eb:a431:5239:3232"),
    ],
    cert: &RootCertificates::Signal,
    proxy_path: "/service",
};

pub const DOMAIN_CONFIG_CHAT_STAGING: DomainConfig = DomainConfig {
    hostname: "chat.staging.signal.org",
    ip_v4: &[
        ip_addr!(v4, "76.223.72.142"),
        ip_addr!(v4, "13.248.206.115"),
    ],
    ip_v6: &[
        ip_addr!(v6, "2600:9000:a507:ab6d:7b25:2580:8bd6:3b93"),
        ip_addr!(v6, "2600:9000:a61f:527c:2215:cd9:bac6:a2f8"),
    ],
    cert: &RootCertificates::Signal,
    proxy_path: "/service-staging",
};

pub const DOMAIN_CONFIG_CDSI: DomainConfig = DomainConfig {
    hostname: "cdsi.signal.org",
    ip_v4: &[ip_addr!(v4, "40.122.45.194")],
    ip_v6: &[ip_addr!(v6, "2603:1030:7::1")],
    cert: &RootCertificates::Signal,
    proxy_path: "/cdsi",
};

pub const DOMAIN_CONFIG_CDSI_STAGING: DomainConfig = DomainConfig {
    hostname: "cdsi.staging.signal.org",
    ip_v4: &[ip_addr!(v4, "104.43.162.137")],
    ip_v6: &[ip_addr!(v6, "2603:1030:7::732")],
    cert: &RootCertificates::Signal,
    proxy_path: "/cdsi-staging",
};

pub const DOMAIN_CONFIG_SVR2: DomainConfig = DomainConfig {
    hostname: "svr2.signal.org",
    ip_v4: &[ip_addr!(v4, "20.66.40.69")],
    ip_v6: &[],
    cert: &RootCertificates::Signal,
    proxy_path: "/svr2",
};

pub const DOMAIN_CONFIG_SVR2_STAGING: DomainConfig = DomainConfig {
    hostname: "svr2.staging.signal.org",
    ip_v4: &[ip_addr!(v4, "20.253.229.239")],
    ip_v6: &[],
    cert: &RootCertificates::Signal,
    proxy_path: "/svr2-staging",
};

pub const DOMAIN_CONFIG_SVR3_SGX: DomainConfig = DomainConfig {
    hostname: "svr3.signal.org",
    ip_v4: &[ip_addr!(v4, "143.244.220.150")],
    ip_v6: &[],
    cert: &RootCertificates::Signal,
    proxy_path: "/svr3-sgx",
};

pub const DOMAIN_CONFIG_SVR3_SGX_STAGING: DomainConfig = DomainConfig {
    hostname: "backend1.svr3.staging.signal.org",
    ip_v4: &[ip_addr!(v4, "13.88.63.29")],
    ip_v6: &[],
    cert: &RootCertificates::Signal,
    proxy_path: "/svr3-sgx-staging",
};

pub const DOMAIN_CONFIG_SVR3_NITRO: DomainConfig = DomainConfig {
    hostname: "devnull.signal.org",
    ip_v4: &[],
    ip_v6: &[],
    cert: &RootCertificates::Signal,
    proxy_path: "/svr3-nitro",
};

pub const DOMAIN_CONFIG_SVR3_NITRO_STAGING: DomainConfig = DomainConfig {
    hostname: "backend2.svr3.staging.signal.org",
    ip_v4: &[ip_addr!(v4, "75.2.86.85"), ip_addr!(v4, "99.83.239.137")],
    ip_v6: &[],
    cert: &RootCertificates::Signal,
    proxy_path: "/svr3-nitro-staging",
};

const PROXY_CONFIG_F: ProxyConfig = ProxyConfig {
    hostname: "reflector-signal.global.ssl.fastly.net",
    sni_list: &[
        "github.githubassets.com",
        "pinterest.com",
        "www.redditstatic.com",
    ],
};

const PROXY_CONFIG_G: ProxyConfig = ProxyConfig {
    hostname: "reflector-nrgwuv7kwq-uc.a.run.app",
    sni_list: &[
        "www.google.com",
        "android.clients.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "inbox.google.com",
    ],
};

#[derive(Clone, Copy)]
pub struct DomainConfig {
    pub hostname: &'static str,
    pub proxy_path: &'static str,
    pub ip_v4: &'static [Ipv4Addr],
    pub ip_v6: &'static [Ipv6Addr],
    pub cert: &'static RootCertificates,
}

impl DomainConfig {
    pub fn connection_params(&self) -> ConnectionParams {
        let static_dns_map = HashMap::from([(
            self.hostname,
            LookupResult::new(self.ip_v4.into(), self.ip_v6.into()),
        )]);
        ConnectionParams::new(
            self.hostname,
            self.hostname,
            443,
            HttpRequestDecoratorSeq::default(),
            *self.cert,
            Arc::new(DnsResolver::new_with_static_fallback(static_dns_map)),
        )
    }

    pub fn connection_params_with_fallback(&self) -> Vec<ConnectionParams> {
        let direct = self.connection_params();
        let rng = thread_rng();
        let shuffled_g_params = PROXY_CONFIG_G.shuffled_connection_params(
            self.proxy_path,
            direct.dns_resolver.clone(),
            rng.clone(),
        );
        let shuffled_f_params = PROXY_CONFIG_F.shuffled_connection_params(
            self.proxy_path,
            direct.dns_resolver.clone(),
            rng,
        );
        let proxy_params = itertools::interleave(shuffled_g_params, shuffled_f_params);
        iter::once(direct).chain(proxy_params).collect()
    }
}

pub struct ProxyConfig {
    hostname: &'static str,
    sni_list: &'static [&'static str],
}

impl ProxyConfig {
    pub fn shuffled_connection_params<'a>(
        &'a self,
        proxy_path: &'static str,
        dns_resolver: Arc<DnsResolver>,
        mut rng: impl Rng,
    ) -> impl Iterator<Item = ConnectionParams> + 'a {
        let mut sni_list = self.sni_list.to_vec();
        sni_list.shuffle(&mut rng);
        sni_list.into_iter().map(move |sni| {
            ConnectionParams::new(
                sni,
                self.hostname,
                443,
                HttpRequestDecorator::PathPrefix(proxy_path).into(),
                RootCertificates::Native,
                dns_resolver.clone(),
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

pub struct Svr3Env<'a>(EnclaveEndpoint<'a, Sgx>, EnclaveEndpoint<'a, Nitro>);

impl<'a> Svr3Env<'a> {
    #[inline]
    pub fn sgx(&self) -> EnclaveEndpoint<'a, Sgx> {
        self.0
    }

    #[inline]
    pub fn nitro(&self) -> EnclaveEndpoint<'a, Nitro> {
        self.1
    }
}

pub const STAGING: Env<'static, Svr3Env> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT_STAGING,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI_STAGING,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_STAGING),
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2_STAGING,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_STAGING),
    },
    svr3: Svr3Env(
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_SGX_STAGING,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_SGX_STAGING),
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_NITRO_STAGING,
            mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR3_NITRO_STAGING),
        },
    ),
};

pub const PROD: Env<'static, Svr3Env> = Env {
    chat_domain_config: DOMAIN_CONFIG_CHAT,
    cdsi: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_CDSI,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_CDSI_PROD),
    },
    svr2: EnclaveEndpoint {
        domain_config: DOMAIN_CONFIG_SVR2,
        mr_enclave: MrEnclave::new(attest::constants::ENCLAVE_ID_SVR2_PROD),
    },
    svr3: Svr3Env(
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_SGX,
            mr_enclave: MrEnclave::new(&[0; 32]),
        },
        EnclaveEndpoint {
            domain_config: DOMAIN_CONFIG_SVR3_NITRO,
            mr_enclave: MrEnclave::new(&[0; 32]),
        },
    ),
};

pub mod constants {
    pub(crate) const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}
