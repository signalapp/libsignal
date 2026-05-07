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
    // TODO: generate this
    static OPS: LazyLock<HashMap<&'static str, BinprotoToJsonFn>> = LazyLock::new(|| {
        HashMap::from_iter([
            (
                "org.signal.chat.account.LookupUsernameHashRequest",
                expect_binproto_to_json::<crate::proto::chat::account::LookupUsernameHashRequest>
                    as _,
            ),
            (
                "org.signal.chat.account.LookupUsernameLinkRequest",
                expect_binproto_to_json::<crate::proto::chat::account::LookupUsernameLinkRequest>
                    as _,
            ),
        ])
    });

    let op = OPS
        .get(message_name)
        .unwrap_or_else(|| unimplemented!("missing binproto_to_json for {message_name}"));
    op(input)
}

pub fn expect_json_to_binproto_by_name(message_name: &str, input: &str) -> Vec<u8> {
    type JsonToBinprotoFn = fn(&str) -> Vec<u8>;
    // TODO: generate this
    static OPS: LazyLock<HashMap<&'static str, JsonToBinprotoFn>> = LazyLock::new(|| {
        HashMap::from_iter([
            (
                "org.signal.chat.account.LookupUsernameHashResponse",
                expect_json_to_binproto::<crate::proto::chat::account::LookupUsernameHashResponse>
                    as _,
            ),
            (
                "org.signal.chat.account.LookupUsernameLinkResponse",
                expect_json_to_binproto::<crate::proto::chat::account::LookupUsernameLinkResponse>
                    as _,
            ),
        ])
    });

    let op = OPS
        .get(message_name)
        .unwrap_or_else(|| unimplemented!("missing json_to_binproto for {message_name}"));
    op(input)
}
