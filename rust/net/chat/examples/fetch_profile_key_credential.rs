//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::{Parser, ValueEnum};
use libsignal_cli_utils::args::{parse_aci, parse_hex_bytes};
use libsignal_core::Aci;
use libsignal_net::chat::test_support::simple_chat_connection;
use libsignal_net::infra::EnableDomainFronting;
use libsignal_net::infra::route::DirectOrProxyMode;
use libsignal_net_chat::api::profiles::UnauthenticatedChatApi as _;
use libsignal_net_chat::api::{Unauth, UserBasedAuthorization};
use zkgroup::profiles::ProfileKey;

#[derive(Parser)]
struct Config {
    env: Environment,
    #[arg(value_parser=parse_aci)]
    aci: Aci,
    #[arg(value_parser=parse_hex_bytes::<32>)]
    profile_key: [u8; zkgroup::PROFILE_KEY_LEN],
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Environment {
    Staging,
    #[value(alias("prod"))]
    Production,
}

const ZKGROUP_PARAMS_STAGING: &str = "ABSY21VckQcbSXVNCGRYJcfWHiAMZmpTtTELcDmxgdFbtp/bWsSxZdMKzfCp8rvIs8ocCU3B37fT3r4Mi5qAemeGeR2X+/YmOGR5ofui7tD5mDQfstAI9i+4WpMtIe8KC3wU5w3Inq3uNWVmoGtpKndsNfwJrCg0Hd9zmObhypUnSkfYn2ooMOOnBpfdanRtrvetZUayDMSC5iSRcXKpdlukrpzzsCIvEwjwQlJYVPOQPj4V0F4UXXBdHSLK05uoPBCQG8G9rYIGedYsClJXnbrgGYG3eMTG5hnx4X4ntARBgELuMWWUEEfSK0mjXg+/2lPmWcTZWR9nkqgQQP0tbzuiPm74H2wMO4u1Wafe+UwyIlIT9L7KLS19Aw8r4sPrXZSSsOZ6s7M1+rTJN0bI5CKY2PX29y5Ok3jSWufIKcgKOnWoP67d5b2du2ZVJjpjfibNIHbT/cegy/sBLoFwtHogVYUewANUAXIaMPyCLRArsKhfJ5wBtTminG/PAvuBdJ70Z/bXVPf8TVsR292zQ65xwvWTejROW6AZX6aqucUjlENAErBme1YHmOSpU6tr6doJ66dPzVAWIanmO/5mgjNEDeK7DDqQdB1xd03HT2Qs2TxY3kCK8aAb/0iM0HQiXjxZ9HIgYhbtvGEnDKW5ILSUydqH/KBhW4Pb0jZWnqN/YgbWDKeJxnDbYcUob5ZY5Lt5ZCMKuaGUvCJRrCtuugSMaqjowCGRempsDdJEt+cMaalhZ6gczklJB/IbdwENW9KeVFPoFNFzhxWUIS5ML9riVYhAtE6JE5jX0xiHNVIIPthb458cfA8daR0nYfYAUKogQArm0iBezOO+mPk5vCNWI+wwkyFCqNDXz/qxl1gAntuCJtSfq9OC3NkdhQlgYQ==";
const ZKGROUP_PARAMS_PROD: &str = "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw==";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_module(module_path!(), log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let Config {
        env,
        aci,
        profile_key,
    } = Config::parse();
    let (env, zkparams) = match env {
        Environment::Staging => (libsignal_net::env::STAGING, ZKGROUP_PARAMS_STAGING),
        Environment::Production => (libsignal_net::env::PROD, ZKGROUP_PARAMS_PROD),
    };

    let chat_connection = Unauth(
        simple_chat_connection(
            &env,
            EnableDomainFronting::AllDomains,
            DirectOrProxyMode::DirectOnly,
            |_route| true,
        )
        .await?,
    );

    let zkparams: zkgroup::ServerPublicParams =
        zkgroup::deserialize(&BASE64_STANDARD.decode(zkparams).unwrap()).unwrap();
    let profile_key = ProfileKey::create(profile_key);
    let request_context =
        zkparams.create_profile_key_credential_request_context(rand::random(), aci, profile_key);

    let response = chat_connection
        .get_profile_key_credential(
            aci,
            profile_key,
            request_context.get_request(),
            UserBasedAuthorization::AccessKey(profile_key.derive_access_key()),
        )
        .await?;
    _ = zkparams.receive_expiring_profile_key_credential(
        &request_context,
        &response,
        SystemTime::now().into(),
    )?;

    log::info!("success!");
    Ok(())
}
