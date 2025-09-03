//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use clap::{Parser, ValueEnum};
use libsignal_net::chat::test_support::simple_chat_connection;
use libsignal_net::infra::EnableDomainFronting;
use libsignal_net_chat::api::Unauth;
use libsignal_net_chat::api::usernames::UnauthenticatedChatApi;

#[derive(Parser)]
struct Config {
    env: Environment,
    username: String,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Environment {
    Staging,
    #[value(alias("prod"))]
    Production,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_module(module_path!(), log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let Config { env, username } = Config::parse();
    let env = match env {
        Environment::Staging => libsignal_net::env::STAGING,
        Environment::Production => libsignal_net::env::PROD,
    };

    let chat_connection = Unauth(
        simple_chat_connection(&env, EnableDomainFronting::AllDomains, None, |_route| true).await?,
    );

    let username = usernames::Username::new(&username)?;
    if let Some(aci) = chat_connection
        .look_up_username_hash(&username.hash())
        .await?
    {
        log::info!("found {}", aci.service_id_string());
    } else {
        log::info!("no user found");
    }

    Ok(())
}
