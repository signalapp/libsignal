//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::sync::LazyLock;

pub fn expect_binproto_to_json<T: prost::Message + Default + serde::Serialize>(
    input: &[u8],
) -> String {
    serde_json::to_string(&T::decode(input).expect("valid input")).expect("can encode as JSON")
}

pub fn expect_json_to_binproto<T: prost::Message + serde::de::DeserializeOwned>(
    input: &str,
) -> Vec<u8> {
    serde_json::from_str::<T>(input)
        .expect("valid JSON")
        .encode_to_vec()
}

pub fn expect_binproto_to_json_by_name(message_name: &str, input: &[u8]) -> String {
    type BinprotoToJsonFn = fn(&[u8]) -> String;
    macro_rules! entry {
        (crate::proto::chat::$suite:ident::$request:ident) => {
            (
                concat!(
                    "org.signal.chat.",
                    stringify!($suite),
                    ".",
                    stringify!($request)
                ),
                expect_binproto_to_json::<crate::proto::chat::$suite::$request> as BinprotoToJsonFn,
            )
        };
    }

    // TODO: generate this
    static OPS: LazyLock<HashMap<&'static str, BinprotoToJsonFn>> = LazyLock::new(|| {
        HashMap::from_iter([
            entry!(crate::proto::chat::account::LookupUsernameHashRequest),
            entry!(crate::proto::chat::account::LookupUsernameLinkRequest),
            entry!(crate::proto::chat::backup::DeleteAllRequest),
            entry!(crate::proto::chat::backup::GetCdnCredentialsRequest),
            entry!(crate::proto::chat::backup::GetSvrBCredentialsRequest),
            entry!(crate::proto::chat::backup::RefreshRequest),
            entry!(crate::proto::chat::backup::SetPublicKeyRequest),
        ])
    });

    let op = OPS
        .get(message_name)
        .unwrap_or_else(|| unimplemented!("missing binproto_to_json for {message_name}"));
    op(input)
}

pub fn expect_json_to_binproto_by_name(message_name: &str, input: &str) -> Vec<u8> {
    type JsonToBinprotoFn = fn(&str) -> Vec<u8>;
    macro_rules! entry {
        (crate::proto::chat::$suite:ident::$response:ident) => {
            (
                concat!(
                    "org.signal.chat.",
                    stringify!($suite),
                    ".",
                    stringify!($response)
                ),
                expect_json_to_binproto::<crate::proto::chat::$suite::$response>
                    as JsonToBinprotoFn,
            )
        };
    }

    // TODO: generate this
    static OPS: LazyLock<HashMap<&'static str, JsonToBinprotoFn>> = LazyLock::new(|| {
        HashMap::from_iter([
            entry!(crate::proto::chat::account::LookupUsernameHashResponse),
            entry!(crate::proto::chat::account::LookupUsernameLinkResponse),
            entry!(crate::proto::chat::backup::DeleteAllResponse),
            entry!(crate::proto::chat::backup::GetCdnCredentialsResponse),
            entry!(crate::proto::chat::backup::GetSvrBCredentialsResponse),
            entry!(crate::proto::chat::backup::RefreshResponse),
            entry!(crate::proto::chat::backup::SetPublicKeyResponse),
        ])
    });

    let op = OPS
        .get(message_name)
        .unwrap_or_else(|| unimplemented!("missing json_to_binproto for {message_name}"));
    op(input)
}
