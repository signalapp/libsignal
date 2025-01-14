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
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::host::Host;
use libsignal_net::infra::tcp_ssl::proxy::socks::{Protocol, SocksConnector};
use libsignal_net::infra::{Alpn, StreamAndInfo, TransportConnectionParams, TransportConnector};
use libsignal_net_infra::errors::TransportConnectError;
use libsignal_net_infra::route::{
    ConnectorExt as _, ProxyTarget, SocksRoute, TcpRoute, TlsRoute, TlsRouteFragment,
    UnresolvedHost,
};
use tokio::time::Duration;
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    proxy_url: Url,
    #[arg(value_parser = parse_target)]
    target: Target,
    #[arg(long)]
    use_new_connector: bool,
}

#[derive(Clone, Debug)]
struct Target(Host<Arc<str>>, NonZeroU16);

fn parse_target(target: &str) -> Result<Target, &'static str> {
    if let Ok(target) = SocketAddr::from_str(target) {
        let port = NonZeroU16::new(target.port()).ok_or("expected nonzero port")?;
        return Ok(Target(Host::Ip(target.ip()), port));
    }

    let (domain, port) = target.split_once(':').ok_or("expected host:port")?;
    let port = NonZeroU16::from_str(port).map_err(|_| "expected valid port")?;
    Ok(Target(Host::Domain(domain.into()), port))
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let Args {
        proxy_url,
        target,
        use_new_connector,
    } = Args::parse();

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

    let proxy_host = proxy_url.host_str().expect("proxy host was not provided");
    let proxy_port = proxy_url
        .port()
        .expect("proxy port was not provided")
        .try_into()
        .expect("proxy port was zero");

    let dns_resolver = DnsResolver::new(&Default::default());
    let root_certs = RootCertificates::Native;

    let mut connection = if use_new_connector {
        let Target(target_host, target_port) = target;
        let host_name = target_host.to_string().into();
        let target_host = match (resolve_hostname_locally, target_host) {
            (true, host) => ProxyTarget::ResolvedLocally(host.map_domain(UnresolvedHost::from)),
            (false, Host::Ip(ip)) => ProxyTarget::ResolvedLocally(Host::Ip(ip)),
            (false, Host::Domain(domain)) => ProxyTarget::ResolvedRemotely { name: domain },
        };
        let unresolved_route = TlsRoute {
            fragment: TlsRouteFragment {
                root_certs,
                sni: Host::Domain(host_name),
                alpn: None,
            },
            inner: SocksRoute {
                proxy: TcpRoute {
                    address: Host::<Arc<str>>::parse_as_ip_or_domain(proxy_host)
                        .map_domain(UnresolvedHost::from),
                    port: proxy_port,
                },
                target_addr: target_host,
                target_port,
                protocol,
            },
        };
        log::info!("unresolved: {unresolved_route:?}");
        let resolved = libsignal_net::infra::route::resolve_route(&dns_resolver, unresolved_route)
            .await
            .expect("failed to resolve");
        let connector =
            libsignal_net::infra::route::ComposedConnector::<_, _, TransportConnectError>::new(
                libsignal_net::infra::tcp_ssl::StatelessDirect,
                libsignal_net::infra::tcp_ssl::proxy::StatelessProxied,
            );

        const START_NEXT_DELAY: Duration = Duration::from_secs(5);
        let connect_attempts = FuturesUnordered::from_iter(resolved.zip(0..).map(|(route, i)| {
            let connector = &connector;
            async move {
                tokio::time::sleep(START_NEXT_DELAY * i).await;
                log::info!("connecting via: {route:?}");
                connector.connect(route, "main".into()).await
            }
        }));
        // needed to scope the borrow of `connector`
        #[allow(clippy::let_and_return)]
        let connection = connect_attempts
            .filter_map(|r| {
                std::future::ready(match r {
                    Ok(c) => Some(c),
                    Err(e) => {
                        log::info!("connect failure: {e}");
                        None
                    }
                })
            })
            .next()
            .await
            .expect("failed to connect");
        connection
    } else {
        let connector = SocksConnector {
            proxy_host: Host::parse_as_ip_or_domain(proxy_host),
            proxy_port,
            protocol,
            resolve_hostname_locally,
            dns_resolver,
        };

        let Target(host, port) = target;

        let host_name = host.to_string().into();
        let connection_params = TransportConnectionParams {
            sni: Arc::clone(&host_name),
            tcp_host: host,
            port,
            certs: root_certs,
        };
        let StreamAndInfo(connection, info) = connector
            .connect(&connection_params, Alpn::Http1_1)
            .await
            .expect("failed to connect");

        eprintln!("connected to proxy at {}", info.address);
        connection
    };

    eprintln!("connected to proxy, reading from stdin");
    let mut stdinout = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());

    tokio::io::copy_bidirectional(&mut stdinout, &mut connection)
        .await
        .expect("proxying failed");
}
