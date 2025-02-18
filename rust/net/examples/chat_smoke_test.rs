//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use futures_util::{FutureExt, StreamExt};
use libsignal_net::chat::ChatServiceError;
use libsignal_net::env::Svr3Env;
use strum::IntoEnumIterator as _;

#[derive(Parser)]
struct Config {
    env: Environment,
    #[arg(long)]
    limit_to_routes: Vec<RouteType>,
    #[arg(long)]
    try_all_routes: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, strum::EnumString, strum::EnumIter)]
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
    env_logger::builder()
        .filter_module(module_path!(), log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let Config {
        env,
        limit_to_routes,
        try_all_routes,
    } = Config::parse();
    let env = match env {
        Environment::Staging => libsignal_net::env::STAGING,
        Environment::Production => libsignal_net::env::PROD,
    };

    let allowed_route_types = limit_to_routes
        .is_empty()
        .then(|| RouteType::iter().collect())
        .unwrap_or(limit_to_routes);

    let success = if try_all_routes {
        futures_util::stream::iter(allowed_route_types)
            .then(|route_type| {
                test_connection(&env, HashSet::from([route_type])).map(|result| match result {
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
        match test_connection(&env, allowed_route_types.into_iter().collect()).await {
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
    env: &libsignal_net::env::Env<'static, Svr3Env<'static>>,
    route_types: HashSet<RouteType>,
) -> Result<(), ChatServiceError> {
    let front_names = route_types
        .into_iter()
        .map(|route_type| match route_type {
            RouteType::Direct => None,
            RouteType::ProxyF => Some(libsignal_net_infra::RouteType::ProxyF.into()),
            RouteType::ProxyG => Some(libsignal_net_infra::RouteType::ProxyG.into()),
        })
        .collect::<HashSet<Option<&'static str>>>();

    use libsignal_net::chat::test_support::simple_chat_connection;
    let chat_connection = simple_chat_connection(env, |route| {
        front_names.contains(&route.fragment.front_name)
    })
    .await?;

    // Disconnect immediately to confirm connection and disconnection works.
    chat_connection.disconect().await;

    log::info!("completed successfully");
    Ok(())
}
