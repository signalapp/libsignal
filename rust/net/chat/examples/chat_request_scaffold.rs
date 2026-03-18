//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! A stripped-down template for sending one (1) request to the chat server.
//!
//! Fill it in with your own request when you need to do one-off testing of unauthenticated APIs.
//! (Authenticated APIs require a proper Signal account.)
//!
//! Run with
//!
//! ```shell
//! cargo run -p libsignal-net-chat --example chat_request_scaffold
//! ```

use clap::{Parser, ValueEnum};
use libsignal_net::chat::test_support::simple_chat_connection;
use libsignal_net::infra::EnableDomainFronting;
use libsignal_net::infra::route::{DirectOrProxyMode, HttpVersion};
use libsignal_net_chat::api::Unauth;
use libsignal_net_chat::api::profiles::UnauthenticatedAccountExistenceApi;

#[derive(Parser)]
struct Config {
    #[arg(default_value = "production")]
    env: Environment,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Environment {
    Staging,
    #[value(alias("prod"))]
    Production,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_module(module_path!(), log::LevelFilter::Info)
        .filter_module("libsignal_net_chat", log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let Config { env } = Config::parse();
    let (mut env, new_host) = match env {
        Environment::Staging => (libsignal_net::env::STAGING, "grpc.chat.staging.signal.org"),
        Environment::Production => (libsignal_net::env::PROD, "grpc.chat.signal.org"),
    };

    // This is cheating, but we're just using it for testing anyway.
    env.chat_domain_config.connect.hostname = new_host;
    env.chat_domain_config.ip_v4 = &[];
    env.chat_domain_config.ip_v6 = &[];
    env.chat_domain_config.connect.http_version = Some(HttpVersion::Http2);

    let chat_connection = simple_chat_connection(
        &env,
        EnableDomainFronting::No,
        DirectOrProxyMode::DirectOnly,
        |_route| true,
    )
    .await?;

    #[allow(unused)]
    let grpc_connection = Unauth(
        chat_connection
            .shared_h2_connection()
            .await
            .expect("H2 connection available"),
    );
    #[allow(unused)]
    let ws_connection = Unauth(chat_connection);

    let result = {
        // *** Replace this example request with your own. ***
        grpc_connection
            .account_exists(libsignal_core::Aci::from_uuid_bytes([0; 16]).into())
            .await
    };

    println!("\n{:#?}", result?);
    Ok(())
}
