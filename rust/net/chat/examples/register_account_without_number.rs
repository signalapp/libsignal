//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Registers an account that has no phone number.
//!
//! Derives the presentation the server wants from the receipt credential provided.
//! Everything else is generated per run, so each invocation creates a new account.
//!
//! Run with
//!
//! ```shell
//! cargo run -p libsignal-net-chat --example register_account_without_number -- \
//!     --receipt-credential "$CREDENTIAL"
//! ```
//!
//! or put it in the environment instead:
//!
//! ```shell
//! RECEIPT_CREDENTIAL="..." \
//!     cargo run -p libsignal-net-chat --example register_account_without_number
//! ```

use std::collections::HashSet;
use std::convert::Infallible;

use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, ValueEnum};
use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use libsignal_net::chat::test_support::simple_chat_connection;
use libsignal_net::chat::{ChatConnection, ConnectError as ChatConnectError};
use libsignal_net::infra::EnableDomainFronting;
use libsignal_net::infra::route::DirectOrProxyMode;
use libsignal_net_chat::api::Unauth;
use libsignal_net_chat::api::registration::{
    AccountKeys, NewMessageNotification, ProvidedAccountAttributes, SignedPreKeyBody,
    SkipDeviceTransfer,
};
use libsignal_net_chat::registration::{ConnectUnauthChat, register_account_without_number};
use libsignal_protocol::{KeyPair, kem};
use rand::{Rng as _, TryRngCore as _};
use zkgroup::ServerPublicParams;
use zkgroup::receipts::ReceiptCredential;

const PROD_SERVER_PUBLIC_PARAMS: &str = "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw==";
const STAGING_SERVER_PUBLIC_PARAMS: &str = "ABSY21VckQcbSXVNCGRYJcfWHiAMZmpTtTELcDmxgdFbtp/bWsSxZdMKzfCp8rvIs8ocCU3B37fT3r4Mi5qAemeGeR2X+/YmOGR5ofui7tD5mDQfstAI9i+4WpMtIe8KC3wU5w3Inq3uNWVmoGtpKndsNfwJrCg0Hd9zmObhypUnSkfYn2ooMOOnBpfdanRtrvetZUayDMSC5iSRcXKpdlukrpzzsCIvEwjwQlJYVPOQPj4V0F4UXXBdHSLK05uoPBCQG8G9rYIGedYsClJXnbrgGYG3eMTG5hnx4X4ntARBgELuMWWUEEfSK0mjXg+/2lPmWcTZWR9nkqgQQP0tbzuiPm74H2wMO4u1Wafe+UwyIlIT9L7KLS19Aw8r4sPrXZSSsOZ6s7M1+rTJN0bI5CKY2PX29y5Ok3jSWufIKcgKOnWoP67d5b2du2ZVJjpjfibNIHbT/cegy/sBLoFwtHogVYUewANUAXIaMPyCLRArsKhfJ5wBtTminG/PAvuBdJ70Z/bXVPf8TVsR292zQ65xwvWTejROW6AZX6aqucUjlENAErBme1YHmOSpU6tr6doJ66dPzVAWIanmO/5mgjNEDeK7DDqQdB1xd03HT2Qs2TxY3kCK8aAb/0iM0HQiXjxZ9HIgYhbtvGEnDKW5ILSUydqH/KBhW4Pb0jZWnqN/YgbWDKeJxnDbYcUob5ZY5Lt5ZCMKuaGUvCJRrCtuugSMaqjowCGRempsDdJEt+cMaalhZ6gczklJB/IbdwENW9KeVFPoFNFzhxWUIS5ML9riVYhAtE6JE5jX0xiHNVIIPthb458cfA8daR0nYfYAUKogQArm0iBezOO+mPk5vCNWI+wwkyFCqNDXz/qxl1gAntuCJtSfq9OC3NkdhQlgYQ==";

#[derive(Parser)]
struct Config {
    #[arg(long, env = "RECEIPT_CREDENTIAL")]
    receipt_credential: String,

    #[arg(long, default_value = "staging")]
    env: Environment,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Environment {
    Staging,
    #[value(alias("prod"))]
    Production,
}

struct ConnectChat {
    env: libsignal_net::env::Env<'static>,
}

impl ConnectUnauthChat for ConnectChat {
    fn connect_chat(
        &self,
        on_disconnect: tokio::sync::oneshot::Sender<Infallible>,
    ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ChatConnectError>> {
        async move {
            let connection = simple_chat_connection(
                &self.env,
                EnableDomainFronting::No,
                DirectOrProxyMode::DirectOnly,
                |_route| true,
            )
            .await?;
            // Intentional leak to let connection outlive a single request we send over it.
            std::mem::forget(on_disconnect);
            Ok(Unauth(connection))
        }
        .boxed()
    }
}

fn signed_pre_key(
    identity: &KeyPair,
    rng: &mut (impl rand::Rng + rand::CryptoRng),
) -> (u32, Box<[u8]>, Box<[u8]>) {
    let public_key = KeyPair::generate(&mut *rng).public_key.serialize();
    let signature = identity
        .private_key
        .calculate_signature(&public_key, &mut *rng)
        .expect("can sign with a freshly generated key");
    (rng.random_range(0..0xFF_FFFF), public_key, signature)
}

fn pq_last_resort_pre_key(
    identity: &KeyPair,
    rng: &mut (impl rand::Rng + rand::CryptoRng),
) -> (u32, Box<[u8]>, Box<[u8]>) {
    let public_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut *rng)
        .public_key
        .serialize();
    let signature = identity
        .private_key
        .calculate_signature(&public_key, &mut *rng)
        .expect("can sign with a freshly generated key");
    (rng.random_range(0..0xFF_FFFF), public_key, signature)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::try_init();

    let Config {
        receipt_credential,
        env,
    } = Config::parse();

    let server_public_params = match env {
        Environment::Staging => STAGING_SERVER_PUBLIC_PARAMS,
        Environment::Production => PROD_SERVER_PUBLIC_PARAMS,
    };
    let server_public_params: ServerPublicParams =
        zkgroup::deserialize(&BASE64_STANDARD.decode(server_public_params)?)
            .expect("hardcoded server public params are valid");
    let decoded = BASE64_URL_SAFE_NO_PAD.decode(&receipt_credential)?;

    let env = match env {
        Environment::Staging => libsignal_net::env::STAGING,
        Environment::Production => libsignal_net::env::PROD,
    };

    let mut rng = rand::rngs::OsRng.unwrap_err();

    let credential: ReceiptCredential = zkgroup::deserialize(&decoded)
        .map_err(|_| anyhow::anyhow!("failed to deserialize the credential"))?;
    let presentation =
        server_public_params.create_receipt_credential_presentation(rng.random(), &credential);

    let identity = KeyPair::generate(&mut rng);
    let (spk_id, spk_public, spk_signature) = signed_pre_key(&identity, &mut rng);
    let (pq_id, pq_public, pq_signature) = pq_last_resort_pre_key(&identity, &mut rng);

    let account_password: String = std::iter::repeat_with(|| rng.random_range('a'..='z'))
        .take(42)
        .collect();
    let recovery_password: [u8; 32] = rng.random();
    let unidentified_access_key: [u8; 16] = rng.random();
    let registration_id = rng.random_range(1..=0x3FFC);

    let account_attributes = ProvidedAccountAttributes {
        recovery_password: &recovery_password,
        registration_id,
        name: None,
        registration_lock: None,
        unidentified_access_key: &unidentified_access_key,
        unrestricted_unidentified_access: false,
        capabilities: HashSet::from_iter(["spqr"]),
        discoverable_by_phone_number: false,
    };

    let response = register_account_without_number(
        &presentation,
        Box::new(ConnectChat { env }),
        NewMessageNotification::WillFetchMessages,
        account_attributes,
        Some(SkipDeviceTransfer),
        AccountKeys {
            identity_key: &identity.public_key,
            signed_pre_key: SignedPreKeyBody {
                key_id: spk_id,
                public_key: &spk_public,
                signature: &spk_signature,
            },
            pq_last_resort_pre_key: SignedPreKeyBody {
                key_id: pq_id,
                public_key: &pq_public,
                signature: &pq_signature,
            },
        },
        &account_password,
    )
    .await;

    println!("\n{response:#?}");

    if let Ok(response) = &response {
        println!("\nAccount password: {account_password}");
        println!(
            "Recovery password: {}",
            BASE64_STANDARD.encode(recovery_password)
        );
        println!("ACI: {}", response.aci.service_id_string());
    }

    Ok(())
}
