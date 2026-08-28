//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;
use std::num::NonZero;
use std::process::ExitCode;
use std::sync::OnceLock;

use clap::{Parser, ValueEnum};
use futures_util::{FutureExt, StreamExt};
use itertools::Itertools;
use libsignal_net::chat::ConnectError;
use libsignal_net::connect_state::infer_proxy_mode_for_config;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::{
    ConnectionProxyConfig, DirectOrProxyMode, ReflectorProviderConfig, SIGNAL_TLS_PROXY_SCHEME,
};
use libsignal_net_infra::{AsStaticHttpHeader, EnableDomainFronting};
use strum::IntoEnumIterator as _;
use url::Url;

#[derive(Parser)]
struct Config {
    env: Environment,
    #[arg(long, conflicts_with = "proxy_url")]
    limit_to_routes: Vec<RouteType>,
    #[arg(long, conflicts_with = "proxy_url")]
    try_all_routes: bool,
    #[arg(long)]
    proxy_url: Option<String>,
    #[arg(long, requires = "proxy_url")]
    allow_proxy_fallback: Option<bool>,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, strum::EnumString, strum::EnumIter)]
#[strum(serialize_all = "lowercase")]
enum RouteType {
    Direct,
    ProxyF,
    ProxyG,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Environment {
    Staging,
    #[value(alias("prod"))]
    Production,
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::new()
        .filter_module(module_path!(), log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let Config {
        env,
        limit_to_routes,
        try_all_routes,
        proxy_url,
        allow_proxy_fallback,
        dry_run,
    } = Config::parse();
    let env = match env {
        Environment::Staging => libsignal_net::env::STAGING,
        Environment::Production => libsignal_net::env::PROD,
    };

    let allowed_route_types = if limit_to_routes.is_empty() {
        RouteType::iter().collect()
    } else {
        limit_to_routes
    };

    let snis = allowed_route_types
        .iter()
        .flat_map(|route_type| {
            let libsignal_net_type = match route_type {
                RouteType::Direct => {
                    return std::slice::from_ref(&env.chat_domain_config.connect.hostname);
                }
                RouteType::ProxyF => libsignal_net_infra::RouteType::ProxyF,
                RouteType::ProxyG => libsignal_net_infra::RouteType::ProxyG,
            };
            let reflectors = (env.reflector_providers)();
            reflectors
                .iter()
                .find(|next| next.route_type == libsignal_net_type)
                .expect("has matching reflector")
                .sni_list
        })
        .copied()
        .collect_vec();

    let env = if try_all_routes {
        split_up_reflectors(env)
    } else {
        env
    };

    let proxy_mode = DirectOrProxyMode::DirectThenProxy(ConnectionProxyConfig::Reflector {
        providers: (env.reflector_providers)(),
        user_agent: libsignal_net::env::UserAgent::with_libsignal_version("chat_smoke_test")
            .header_value(),
    });

    let proxy_mode = proxy_url.map_or(proxy_mode, |url| {
        let url = Url::parse(&url)
            .inspect_err(|_| {
                log::warn!("did you mean to prefix with {SIGNAL_TLS_PROXY_SCHEME}:// ?");
            })
            .expect("proxy URL was invalid");
        let authority = (|| {
            if url.username().is_empty() {
                return None;
            }
            let password = url.password()?;
            Some((url.username().to_owned(), password.to_owned()))
        })();
        let config = ConnectionProxyConfig::from_parts(
            url.scheme(),
            url.host_str().expect("host was not provided"),
            url.port().and_then(NonZero::new),
            authority,
        )
        .unwrap();
        match allow_proxy_fallback {
            Some(true) => DirectOrProxyMode::ProxyThenDirect(config),
            Some(false) => DirectOrProxyMode::ProxyOnly(config),
            None => infer_proxy_mode_for_config(config),
        }
    });

    let success = if try_all_routes {
        futures_util::stream::iter(snis)
            .then(|sni| {
                log::info!("## Trying {sni} ##");
                // We generate every route (cf split_up_reflectors above), then filter for the
                // specific one we're trying to test.
                test_connection(&env, HashSet::from_iter([sni]), proxy_mode.clone(), dry_run).map(
                    |result| match result {
                        Ok(()) => true,
                        Err(e) => {
                            log::error!("failed to connect: {e}");
                            false
                        }
                    },
                )
            })
            .fold(true, |a, b| std::future::ready(a && b))
            .await
    } else {
        match test_connection(&env, HashSet::from_iter(snis), proxy_mode, dry_run).await {
            Ok(()) => true,
            Err(e) => {
                log::error!("failed to connect: {e}");
                false
            }
        }
    };

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Rewrites the reflectors in `env` from N options with M SNIs to M*N options with 1 SNI each.
///
/// Can only be called once, as part of satisfying the `fn` requirement of `reflector_providers`.
fn split_up_reflectors(env: libsignal_net::env::Env<'static>) -> libsignal_net::env::Env<'static> {
    static SPLIT_UP_REFLECTORS: OnceLock<Vec<ReflectorProviderConfig>> = OnceLock::new();

    let reflectors = (env.reflector_providers)();
    SPLIT_UP_REFLECTORS
        .set(
            reflectors
                .iter()
                .flat_map(|next| {
                    next.sni_list.iter().map(|sni| ReflectorProviderConfig {
                        route_type: next.route_type,
                        http_host: next.http_host,
                        sni_list: std::slice::from_ref(sni),
                        certs: next.certs.clone(),
                        endpoint: next.endpoint.clone(),
                    })
                })
                .collect_vec(),
        )
        .expect("not initialized yet");

    libsignal_net::env::Env {
        reflector_providers: || SPLIT_UP_REFLECTORS.get().expect("initialized"),
        ..env
    }
}

async fn test_connection(
    env: &libsignal_net::env::Env<'static>,
    snis: HashSet<&str>,
    proxy_mode: DirectOrProxyMode,
    dry_run: bool,
) -> Result<(), ConnectError> {
    use libsignal_net::chat::test_support::simple_chat_connection;
    let chat_connection =
        simple_chat_connection(env, EnableDomainFronting::No, proxy_mode, |route| {
            let chat_sni = match &route.inner.fragment.sni {
                Host::Domain(domain) => domain,
                Host::Ip(_) => panic!("unexpected IP address as a chat SNI"),
            };
            let immediate_sni: &str = match &route.inner.inner {
                libsignal_net_infra::route::DirectOrProxyRoute::Direct(_) => chat_sni,
                libsignal_net_infra::route::DirectOrProxyRoute::Proxy(
                    libsignal_net_infra::route::ConnectionProxyRoute::Reflector(reflector),
                ) => match &reflector.outer.inner.inner.fragment.sni {
                    Host::Domain(domain) => domain,
                    Host::Ip(_) => panic!("unexpected IP address as a reflector SNI"),
                },
                libsignal_net_infra::route::DirectOrProxyRoute::Proxy(_) => chat_sni,
            };
            if !snis.contains(immediate_sni) {
                return false;
            }
            log::debug!("{route:#?}");
            !dry_run
        })
        .await;

    match chat_connection {
        Ok(connection) => {
            // Disconnect immediately to confirm connection and disconnection works.
            connection.disconnect().await;
            log::info!("completed successfully");
            Ok(())
        }
        Err(ConnectError::AllAttemptsFailed) if dry_run => Ok(()),
        Err(e) => Err(e),
    }
}
