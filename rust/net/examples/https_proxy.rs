//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Connects to a provided proxy host and then shuffles bytes to/from stdout/stdin.
//!
//! This makes an HTTP request through an HTTPS proxy:
//! ```text
//! #!/bin/bash
//! # This example uses https://tinyproxy.github.io/ with the following config:
//! # > Port 8888
//! # > Listen 127.0.0.1
//! # > Allow 127.0.0.1
//! PROXY_URL=http://127.0.0.1:8888;
//! # Send an HTTP 1.1 request, then hold STDIN open so the example doesn't exit.
//! bash -c 'echo -en "GET / HTTP/1.1\r\nHost: signal.org\r\n\r\n"; cat' | \
//! # Run the example, pointing it at an HTTP(S) proxy that supports CONNECT.
//! cargo run -p libsignal-net --example https_proxy -- $PROXY_URL signal.org:80
//! ```

use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use either::Either;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::host::Host;
use libsignal_net_infra::route::{
    ConnectorExt as _, HttpProxyAuth, HttpProxyRouteFragment, HttpsProxyRoute, ProxyTarget,
    TcpRoute, TlsRoute, TlsRouteFragment, UnresolvedHost,
};
use libsignal_net_infra::Alpn;
use tokio::time::Duration;
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    proxy_url: Url,
    #[arg(value_parser = parse_target)]
    target: Target,

    #[arg(default_value_t = false, long)]
    resolve_hostname_locally: bool,
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
        resolve_hostname_locally,
    } = Args::parse();

    let proxy_host = Host::<Arc<str>>::parse_as_ip_or_domain(
        proxy_url.host_str().expect("proxy host was not provided"),
    );
    let proxy_port = proxy_url
        .port_or_known_default()
        .expect("proxy port was not provided")
        .try_into()
        .expect("proxy port was zero");

    let root_certs = RootCertificates::Native;
    let tcp_to_proxy = TcpRoute {
        address: proxy_host.clone().map_domain(UnresolvedHost::from),
        port: proxy_port,
    };
    let inner = match proxy_url.scheme() {
        "http" => Either::Right(tcp_to_proxy),
        "https" => Either::Left(TlsRoute {
            inner: tcp_to_proxy,
            fragment: TlsRouteFragment {
                root_certs,
                sni: proxy_host.clone(),
                alpn: Some(Alpn::Http1_1),
            },
        }),
        scheme => panic!("unsupported protocol {scheme}"),
    };
    let username = (!proxy_url.username().is_empty()).then_some(proxy_url.username());
    let authorization = match (username, proxy_url.password()) {
        (Some(username), Some(password)) => Some(HttpProxyAuth {
            username: username.to_owned(),
            password: password.to_owned(),
        }),
        (None, None) => None,
        _ => panic!("only one of username or password was provided"),
    };

    let dns_resolver = DnsResolver::new(&Default::default());

    let Target(target_host, target_port) = target;
    let target_host = match (resolve_hostname_locally, target_host) {
        (true, host) => ProxyTarget::ResolvedLocally(host.map_domain(UnresolvedHost::from)),
        (false, Host::Ip(ip)) => ProxyTarget::ResolvedLocally(Host::Ip(ip)),
        (false, Host::Domain(domain)) => ProxyTarget::ResolvedRemotely { name: domain },
    };
    let unresolved_route = HttpsProxyRoute {
        inner,
        fragment: HttpProxyRouteFragment {
            target_host,
            target_port,
            authorization,
        },
    };
    log::info!("unresolved: {unresolved_route:?}");
    let resolved = libsignal_net::infra::route::resolve_route(&dns_resolver, unresolved_route)
        .await
        .expect("failed to resolve");
    let connector = libsignal_net::infra::tcp_ssl::proxy::StatelessProxied;

    const START_NEXT_DELAY: Duration = Duration::from_secs(5);
    let connect_attempts = FuturesUnordered::from_iter(resolved.zip(0..).map(|(route, i)| {
        let connector = &connector;
        async move {
            tokio::time::sleep(START_NEXT_DELAY * i).await;
            log::info!("connecting via: {route:?}");
            connector.connect(route, "main".into()).await
        }
    }));
    let mut connection = connect_attempts
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

    eprintln!("connected to proxy, reading from stdin");
    let mut stdinout = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());

    tokio::io::copy_bidirectional(&mut stdinout, &mut connection)
        .await
        .expect("proxying failed");
}
