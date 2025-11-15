//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use attest::svr2::RaftConfig;
use const_str::ip_addr;
use libsignal_net::chat::RECOMMENDED_CHAT_WS_CONFIG;
use libsignal_net::enclave::{Cdsi, EnclaveEndpoint, EndpointParams, MrEnclave, SvrSgx};
use libsignal_net::env::{ConnectionConfig, DomainConfig, Env, KeyTransConfig, SvrBEnv};
use libsignal_net::infra::RECOMMENDED_WS_CONFIG;
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::route::HttpVersion;

const ENCLAVE_ID_MOCK_SERVER: &[u8] = b"0.20240911.184407";

fn localhost_test_domain_config_with_port_and_cert(
    port: NonZeroU16,
    root_certificate_der: &[u8],
) -> DomainConfig {
    const LOCALHOST_IP_V4: Ipv4Addr = ip_addr!(v4, "127.0.0.1");
    DomainConfig {
        ip_v4: &[LOCALHOST_IP_V4],
        ip_v6: &[],
        connect: ConnectionConfig {
            hostname: "localhost",
            port,
            cert: RootCertificates::FromDer(std::borrow::Cow::Owned(root_certificate_der.to_vec())),
            http_version: Some(HttpVersion::Http1_1),
            min_tls_version: None,
            confirmation_header_name: None,
            proxy: None,
        },
    }
}

pub(crate) struct LocalhostEnvPortConfig {
    pub(crate) chat_port: NonZeroU16,
    pub(crate) cdsi_port: NonZeroU16,
    pub(crate) svr2_port: NonZeroU16,
    pub(crate) svrb_port: NonZeroU16,
}

const DUMMY_RAFT_CONFIG: &RaftConfig = &RaftConfig {
    min_voting_replicas: 3,
    max_voting_replicas: 9,
    super_majority: 0,
    group_id: 17325409821474389983,
    attestation_timeout: 604800,
    db_version: 2,
    simulated: false,
};

const DUMMY_CDSI_ENDPOINT_PARAMS: EndpointParams<'static, Cdsi> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: (),
};

const DUMMY_SVR2_ENDPOINT_PARAMS: EndpointParams<'static, SvrSgx> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: DUMMY_RAFT_CONFIG,
};

const DUMMY_SVRB_ENDPOINT_PARAMS: EndpointParams<'static, SvrSgx> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: DUMMY_RAFT_CONFIG,
};

const DUMMY_KEYTRANS_CONFIG: KeyTransConfig = KeyTransConfig {
    signing_key_material: &[0; 32],
    vrf_key_material: &[0; 32],
    auditor_key_material: &[&[0; 32]],
};

pub(crate) fn localhost_test_env_with_ports(
    ports: LocalhostEnvPortConfig,
    root_certificate_der: &[u8],
) -> Env<'static> {
    Env {
        chat_domain_config: localhost_test_domain_config_with_port_and_cert(
            ports.chat_port,
            root_certificate_der,
        ),
        chat_ws_config: RECOMMENDED_CHAT_WS_CONFIG,
        cdsi: EnclaveEndpoint {
            domain_config: localhost_test_domain_config_with_port_and_cert(
                ports.cdsi_port,
                root_certificate_der,
            ),
            ws_config: RECOMMENDED_WS_CONFIG,
            params: DUMMY_CDSI_ENDPOINT_PARAMS,
        },
        svr2: EnclaveEndpoint {
            domain_config: localhost_test_domain_config_with_port_and_cert(
                ports.svr2_port,
                root_certificate_der,
            ),
            ws_config: RECOMMENDED_WS_CONFIG,
            params: DUMMY_SVR2_ENDPOINT_PARAMS,
        },
        svr_b: SvrBEnv::new(
            [
                Some(EnclaveEndpoint {
                    domain_config: localhost_test_domain_config_with_port_and_cert(
                        ports.svrb_port,
                        root_certificate_der,
                    ),
                    ws_config: RECOMMENDED_WS_CONFIG,
                    params: DUMMY_SVRB_ENDPOINT_PARAMS,
                }),
                None,
                None,
            ],
            [None, None, None],
        ),
        keytrans_config: DUMMY_KEYTRANS_CONFIG,
    }
}
