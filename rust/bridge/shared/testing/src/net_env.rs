//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use attest::constants::RAFT_CONFIG_SVR3_SGX_STAGING;
use attest::svr2::RaftConfig;
use const_str::ip_addr;
use libsignal_net::enclave::{
    Cdsi, EnclaveEndpoint, EndpointParams, MrEnclave, Nitro, Sgx, SgxPreQuantum, Tpm2Snp,
};
use libsignal_net::env::{ConnectionConfig, DomainConfig, Env, Svr3Env};
use libsignal_net::infra::certs::RootCertificates;

// Taken from ENCLAVE_ID_SVR3_TPM2SNP_STAGING
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
            confirmation_header_name: None,
            proxy: None,
        },
    }
}

pub(crate) struct LocalhostEnvPortConfig {
    pub(crate) chat_port: NonZeroU16,
    pub(crate) cdsi_port: NonZeroU16,
    pub(crate) svr2_port: NonZeroU16,
    pub(crate) svr3_sgx_port: NonZeroU16,
    pub(crate) svr3_nitro_port: NonZeroU16,
    pub(crate) svr3_tpm2_snp_port: NonZeroU16,
}

const DUMMY_RAFT_CONFIG: &RaftConfig = RAFT_CONFIG_SVR3_SGX_STAGING;

const DUMMY_CDSI_ENDPOINT_PARAMS: EndpointParams<'static, Cdsi> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: (),
};

const DUMMY_SVR2_ENDPOINT_PARAMS: EndpointParams<'static, SgxPreQuantum> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: DUMMY_RAFT_CONFIG,
};

const DUMMY_SGX_ENDPOINT_PARAMS: EndpointParams<'static, Sgx> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: DUMMY_RAFT_CONFIG,
};

const DUMMY_NITRO_ENDPOINT_PARAMS: EndpointParams<'static, Nitro> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: DUMMY_RAFT_CONFIG,
};

const DUMMY_TPM2SNP_ENDPOINT_PARAMS: EndpointParams<'static, Tpm2Snp> = EndpointParams {
    mr_enclave: MrEnclave::new(ENCLAVE_ID_MOCK_SERVER),
    raft_config: DUMMY_RAFT_CONFIG,
};

pub(crate) fn localhost_test_env_with_ports(
    ports: LocalhostEnvPortConfig,
    root_certificate_der: &[u8],
) -> Env<'static, Svr3Env<'static>> {
    Env {
        chat_domain_config: localhost_test_domain_config_with_port_and_cert(
            ports.chat_port,
            root_certificate_der,
        ),
        cdsi: EnclaveEndpoint {
            domain_config: localhost_test_domain_config_with_port_and_cert(
                ports.cdsi_port,
                root_certificate_der,
            ),
            params: DUMMY_CDSI_ENDPOINT_PARAMS,
        },
        svr2: EnclaveEndpoint {
            domain_config: localhost_test_domain_config_with_port_and_cert(
                ports.svr2_port,
                root_certificate_der,
            ),
            params: DUMMY_SVR2_ENDPOINT_PARAMS,
        },
        svr3: Svr3Env::new(
            EnclaveEndpoint {
                domain_config: localhost_test_domain_config_with_port_and_cert(
                    ports.svr3_sgx_port,
                    root_certificate_der,
                ),
                params: DUMMY_SGX_ENDPOINT_PARAMS,
            },
            EnclaveEndpoint {
                domain_config: localhost_test_domain_config_with_port_and_cert(
                    ports.svr3_nitro_port,
                    root_certificate_der,
                ),
                params: DUMMY_NITRO_ENDPOINT_PARAMS,
            },
            EnclaveEndpoint {
                domain_config: localhost_test_domain_config_with_port_and_cert(
                    ports.svr3_tpm2_snp_port,
                    root_certificate_der,
                ),
                params: DUMMY_TPM2SNP_ENDPOINT_PARAMS,
            },
        ),
        keytrans_config: None,
    }
}
