//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;
use std::num::NonZero;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use futures_util::{FutureExt, StreamExt};
use libsignal_net::chat::ConnectError;
use libsignal_net::connect_state::infer_proxy_mode_for_config;
use libsignal_net_infra::EnableDomainFronting;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::{
    ConnectionProxyConfig, DirectOrProxyMode, SIGNAL_TLS_PROXY_SCHEME,
};
use strum::IntoEnumIterator as _;
use url::Url;

#[derive(Parser)]
struct Config {
    env: Environment,
    #[arg(long)]
    limit_to_routes: Vec<RouteType>,
    #[arg(long)]
    try_all_routes: bool,
    #[arg(long)]
    proxy_url: Option<String>,
    #[arg(long)]
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

    let snis = allowed_route_types.iter().flat_map(|route_type| {
        let (index, libsignal_net_type) = match route_type {
            RouteType::Direct => {
                return std::slice::from_ref(&env.chat_domain_config.connect.hostname);
            }
            RouteType::ProxyF => (0, libsignal_net_infra::RouteType::ProxyF),
            RouteType::ProxyG => (1, libsignal_net_infra::RouteType::ProxyG),
        };
        let config = &env
            .chat_domain_config
            .connect
            .proxy
            .as_ref()
            .expect("configured")
            .configs[index];
        assert_eq!(
            config.route_type(),
            libsignal_net_type,
            "wrong index for {route_type:?}"
        );
        config.hostnames()
    });

    let proxy_mode = proxy_url.map_or(DirectOrProxyMode::DirectOnly, |url| {
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
            .then(|&sni| {
                log::info!("## Trying {sni} ##");
                // We use AllDomains mode to generate every route, then filter for the specific one
                // we're trying to test.
                test_connection(
                    &env,
                    HashSet::from([sni]),
                    EnableDomainFronting::AllDomains,
                    proxy_mode.clone(),
                    dry_run,
                )
                .map(|result| match result {
                    Ok(()) => true,
                    Err(e) => {
                        log::error!("failed to connect: {e}");
                        false
                    }
                })
            })
            .fold(true, |a, b| std::future::ready(a && b))
            .await
    } else {
        let domain_fronting = if allowed_route_types == [RouteType::Direct] {
            EnableDomainFronting::No
        } else {
            EnableDomainFronting::OneDomainPerProxy
        };
        match test_connection(
            &env,
            snis.copied().collect(),
            domain_fronting,
            proxy_mode,
            dry_run,
        )
        .await
        {
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

async fn test_connection(
    env: &libsignal_net::env::Env<'static>,
    snis: HashSet<&str>,
    domain_fronting: EnableDomainFronting,
    proxy_mode: DirectOrProxyMode,
    dry_run: bool,
) -> Result<(), ConnectError> {
    use libsignal_net::chat::test_support::simple_chat_connection;
    let chat_connection = simple_chat_connection(env, domain_fronting, proxy_mode, |route| {
        match &route.inner.fragment.sni {
            Host::Domain(domain) => {
                if !snis.contains(&domain[..]) {
                    return false;
                }
            }
            Host::Ip(_) => panic!("unexpected IP address as a chat SNI"),
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
