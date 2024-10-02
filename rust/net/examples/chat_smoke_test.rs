//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::process::ExitCode;

use clap::{Args, Parser, ValueEnum};
use libsignal_net::auth::Auth;
use libsignal_net::chat::test_support::simple_chat_service;
use libsignal_net::chat::ChatServiceError;
use libsignal_net::env::Svr3Env;
use libsignal_net::infra::{ConnectionParams, RouteType};

#[derive(Parser)]
struct Config {
    #[clap(flatten)]
    route: Option<Route>,
    env: Environment,
    #[arg(long)]
    try_all_routes: bool,
}

#[derive(Args)]
#[group(multiple = false)]
struct Route {
    #[arg(long)]
    proxy_g: bool,
    #[arg(long)]
    proxy_f: bool,
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

    let config = Config::parse();
    let env = match config.env {
        Environment::Staging => libsignal_net::env::STAGING,
        Environment::Production => libsignal_net::env::PROD,
    };

    let mut connection_params = env
        .chat_domain_config
        .connect
        .connection_params_with_fallback();
    match config.route {
        Some(Route { proxy_g: true, .. }) => {
            connection_params.retain(|c| c.route_type == RouteType::ProxyG)
        }
        Some(Route { proxy_f: true, .. }) => {
            connection_params.retain(|c| c.route_type == RouteType::ProxyF)
        }
        _ if config.try_all_routes => {
            // Retain every route, including the direct one.
        }
        _ => connection_params.retain(|c| c.route_type == RouteType::Direct),
    };

    let mut any_failures = false;
    if config.try_all_routes {
        for route in connection_params {
            log::info!("trying {} ({})", route.transport.sni, route.route_type);
            test_connection(&env, vec![route])
                .await
                .unwrap_or_else(|e| {
                    any_failures = true;
                    log::error!("failed to connect: {e}")
                });
        }
    } else {
        test_connection(&env, connection_params)
            .await
            .unwrap_or_else(|e| {
                any_failures = true;
                log::error!("failed to connect: {e}")
            });
    }

    if any_failures {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn test_connection(
    env: &libsignal_net::env::Env<'static, Svr3Env<'static>>,
    connection_params: Vec<ConnectionParams>,
) -> Result<(), ChatServiceError> {
    let chat = simple_chat_service(env, Auth::default(), connection_params);

    chat.connect_unauthenticated().await?;
    chat.disconnect().await;
    log::info!("completed successfully");
    Ok(())
}
