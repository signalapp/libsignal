//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! A tool to regenerate attestation test data from live systems.
//!
//! Usage: `cd rust/net ; cargo run --example attest_test_regenerate -- --svr2-staging-auth-secret=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa= --cdsi-staging-auth-secret=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa= --rust-attest-tests-data-dir=$(pwd)/../attest/tests/data/`
//!
//! This tool will overwrite files in `rust/attest/tests/data/` by interacting
//! with the current staging SVR2 and CDSI instances to get new attestation
//! messages.

use std::time::SystemTime;

use attest::enclave;
use attest::enclave::Handshake;
use base64::prelude::{BASE64_STANDARD, Engine};
use clap::Parser as _;
use http::HeaderName;
use http::uri::PathAndQuery;
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::CdsiConnection;
use libsignal_net::connect_state::{ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::enclave::{Cdsi, EnclaveKind, EndpointParams, MrEnclave, NewHandshake, SvrSgx};
use libsignal_net::svr::SvrConnection;
use libsignal_net_infra::EnableDomainFronting;
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::route::DirectOrProxyProvider;
use libsignal_net_infra::utils::no_network_change_events;
use prost::Message;

#[derive(clap::Parser)]
struct Args {
    #[arg(long, value_parser = parse_auth_secret)]
    svr2_staging_auth_secret: [u8; 32],
    #[arg(long, value_parser = parse_auth_secret)]
    cdsi_staging_auth_secret: [u8; 32],
    #[arg(long)]
    rust_attest_tests_data_dir: String,
}

fn parse_auth_secret(input: &str) -> Result<[u8; 32], base64::DecodeError> {
    BASE64_STANDARD
        .decode(input)?
        .try_into()
        .map_err(|_| base64::DecodeError::InvalidLength(input.len()))
}

struct LoggingNewHandshake<E: EnclaveKind, LL: LoggingLocation>(E, std::marker::PhantomData<LL>);

impl<E: EnclaveKind, LL: LoggingLocation> EnclaveKind for LoggingNewHandshake<E, LL> {
    type RaftConfigType = E::RaftConfigType;

    fn url_path(enclave: &[u8]) -> PathAndQuery {
        E::url_path(enclave)
    }
}

fn cast_params<'a, T, U>(params: &'a EndpointParams<'a, T>) -> EndpointParams<'a, U>
where
    T: EnclaveKind<RaftConfigType = U::RaftConfigType>,
    U: EnclaveKind,
{
    EndpointParams {
        mr_enclave: MrEnclave::new(params.mr_enclave.as_ref()),
        raft_config: params.raft_config.clone(),
    }
}

fn write_file(filename: &str, data: &[u8]) {
    let args = Args::parse();
    log::info!(
        "writing file {filename} into {0}",
        args.rust_attest_tests_data_dir
    );
    let filename = std::path::Path::new(&args.rust_attest_tests_data_dir).join(filename);
    std::fs::write(filename, data).expect("should be able to write file");
}

trait LoggingLocation {
    fn filename_prefix() -> &'static str;
}

struct SVR2LoggingLocation {}
impl LoggingLocation for SVR2LoggingLocation {
    fn filename_prefix() -> &'static str {
        "svr2"
    }
}
struct CDSILoggingLocation {}
impl LoggingLocation for CDSILoggingLocation {
    fn filename_prefix() -> &'static str {
        "cdsi"
    }
}

impl<E: NewHandshake + 'static, LL: LoggingLocation> NewHandshake for LoggingNewHandshake<E, LL> {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<Handshake> {
        write_file(
            (LL::filename_prefix().to_string() + ".handshakestart").as_str(),
            attestation_message,
        );
        let out = E::new_handshake(&cast_params(params), attestation_message).unwrap();
        write_file(
            (LL::filename_prefix().to_string() + ".pubkey").as_str(),
            &out.claims().public_key,
        );
        Ok(out)
    }
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let args = Args::parse();

    let username = "00000000000000000000000000000000".to_string();
    let now = SystemTime::now();
    let now_unix_secs: u64 = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let svr2_password = Auth::otp(username.as_str(), &args.svr2_staging_auth_secret, now);
    let svr2_auth = Auth {
        username: username.clone(),
        password: svr2_password,
    };
    let cdsi_password = Auth::otp(username.as_str(), &args.cdsi_staging_auth_secret, now);
    let cdsi_auth = Auth {
        username: username.clone(),
        password: cdsi_password,
    };

    let env = libsignal_net::env::STAGING;
    let resolver = DnsResolver::new(&no_network_change_events());
    let svr2 = &env.svr2.current;
    let cdsi = &env.cdsi;

    let svr2_mrenclave = svr2.params.mr_enclave.as_ref();
    write_file("svr2.mrenclave", svr2_mrenclave);
    write_file("svr2.timestamp", &now_unix_secs.to_be_bytes()[..]);
    write_file(
        "svr2.group_config",
        &svr2.params.raft_config.as_pb().encode_to_vec(),
    );
    write_file(
        "svr2.advisories",
        attest::get_sw_advisories(svr2_mrenclave)
            .join("\n")
            .as_bytes(),
    );

    let confirmation_header_name = env
        .svr2
        .current
        .domain_config
        .connect
        .confirmation_header_name
        .map(HeaderName::from_static);
    let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
    let connection_resources = ConnectionResources {
        connect_state: &connect_state,
        dns_resolver: &resolver,
        network_change_event: &no_network_change_events(),
        confirmation_header_name,
    };

    let params: EndpointParams<'_, LoggingNewHandshake<SvrSgx, SVR2LoggingLocation>> =
        cast_params(&svr2.params);

    let _connection = SvrConnection::connect(
        connection_resources,
        svr2.domain_config.connect.service,
        DirectOrProxyProvider::direct(
            env.svr2
                .current
                .enclave_websocket_provider(EnableDomainFronting::No),
        ),
        svr2.ws_config,
        &params,
        &svr2_auth,
    )
    .await
    .expect("can connect");

    let cdsi_mrenclave = cdsi.params.mr_enclave.as_ref();
    write_file("cdsi.mrenclave", cdsi_mrenclave);
    write_file("cdsi.timestamp", &now_unix_secs.to_be_bytes()[..]);
    write_file(
        "cdsi.advisories",
        attest::get_sw_advisories(cdsi_mrenclave)
            .join("\n")
            .as_bytes(),
    );

    let confirmation_header_name = env
        .cdsi
        .domain_config
        .connect
        .confirmation_header_name
        .map(HeaderName::from_static);
    let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
    let connection_resources = ConnectionResources {
        connect_state: &connect_state,
        dns_resolver: &resolver,
        network_change_event: &no_network_change_events(),
        confirmation_header_name,
    };

    let params: EndpointParams<'_, LoggingNewHandshake<Cdsi, CDSILoggingLocation>> =
        cast_params(&cdsi.params);

    let _connection = CdsiConnection::connect_with(
        connection_resources,
        cdsi.domain_config.connect.service,
        DirectOrProxyProvider::direct(cdsi.enclave_websocket_provider(EnableDomainFronting::No)),
        cdsi.ws_config,
        &params,
        &cdsi_auth,
    )
    .await
    .unwrap();
}
