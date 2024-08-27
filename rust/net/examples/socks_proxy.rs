//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Connects to a provided proxy host and then shuffles bytes to/from stdout/stdin.

use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::proxy::socks::{Protocol, SocksConnector};
use libsignal_net::infra::{
    Alpn, ConnectionParams, HttpRequestDecoratorSeq, RouteType, StreamAndInfo, TransportConnector,
};
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    proxy_url: Url,
    #[arg(value_parser = parse_target)]
    target: Target,
}

#[derive(Debug)]
struct Target(tokio_socks::TargetAddr<'static>);

impl Clone for Target {
    fn clone(&self) -> Self {
        Self(match &self.0 {
            tokio_socks::TargetAddr::Ip(ip) => tokio_socks::TargetAddr::Ip(*ip),
            tokio_socks::TargetAddr::Domain(domain, port) => {
                tokio_socks::TargetAddr::Domain(domain.clone(), *port)
            }
        })
    }
}

fn parse_target(target: &str) -> Result<Target, &'static str> {
    if let Ok(target) = SocketAddr::from_str(target) {
        return Ok(Target(tokio_socks::TargetAddr::Ip(target)));
    }

    let (domain, port) = target.split_once(':').ok_or("expected host:port")?;
    let port = u16::from_str(port).map_err(|_| "expected numeric port")?;
    Ok(Target(tokio_socks::TargetAddr::Domain(
        std::borrow::Cow::Owned(domain.to_owned()),
        port,
    )))
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let Args { proxy_url, target } = Args::parse();

    let protocol;
    let resolve_hostname_locally;
    let scheme = proxy_url.scheme();
    match scheme {
        "socks" | // Default to SOCKS5
        "socks5" | "socks5h" => {
            let username = (!proxy_url.username().is_empty()).then_some(proxy_url.username());
            let username_password = match (username, proxy_url.password()) {
                (Some(username), Some(password)) => Some((username.to_owned(), password.to_owned())),
                (None, None) => None,
                _ => panic!("only one of username or password was provided"),
            };
            protocol = Protocol::Socks5 { username_password };
            resolve_hostname_locally = !scheme.ends_with('h');
        },
        "socks4" | "socks4a" => {
            let username = proxy_url.username();
            let user_id = (!username.is_empty()).then(|| username.to_owned());
            protocol = Protocol::Socks4 { user_id };
            resolve_hostname_locally = !scheme.ends_with('a');
        }
        proto => panic!("unsupported protocol {proto:?}"),
    };

    let proxy_host = proxy_url
        .host_str()
        .expect("proxy host was not provided")
        .to_owned();
    let proxy_port = proxy_url
        .port()
        .expect("proxy port was not provided")
        .try_into()
        .expect("proxy port was zero");

    let connector = SocksConnector {
        proxy_host,
        proxy_port,
        protocol,
        resolve_hostname_locally,
        dns_resolver: DnsResolver::new(&Default::default()),
    };

    let (host, port) = match target.0 {
        tokio_socks::TargetAddr::Ip(ip) => (ip.ip().to_string(), ip.port()),
        tokio_socks::TargetAddr::Domain(domain, port) => (domain.to_string(), port),
    };

    let host = host.into();
    let connection_params = ConnectionParams {
        route_type: RouteType::SocksProxy,
        sni: Arc::clone(&host),
        host,
        port: NonZeroU16::new(port).expect("target port was zero"),
        http_request_decorator: HttpRequestDecoratorSeq::default(),
        certs: RootCertificates::Native,
        connection_confirmation_header: None,
    };
    let StreamAndInfo(mut connection, info) = connector
        .connect(&connection_params, Alpn::Http1_1)
        .await
        .expect("failed to connect");

    eprintln!("connected to proxy at {}, reading from stdin", info.address);

    let mut stdinout = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());

    tokio::io::copy_bidirectional(&mut stdinout, &mut connection)
        .await
        .expect("proxying failed");
}
