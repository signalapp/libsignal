//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_chat::api::registration::SignedPreKeyBody;
use libsignal_protocol::error::Result;
use libsignal_protocol::*;

use crate::*;

bridge_get!(SessionRecord::alice_base_key -> &[u8], ffi = false, node = false);

/// cbindgen: ignore
type SignedPublicPreKey = SignedPreKeyBody<Box<[u8]>>;

#[bridge_fn]
fn TESTING_SignedPublicPreKey_CheckBridgesCorrectly(
    source_public_key: &PublicKey,
    signed_pre_key: SignedPublicPreKey,
) {
    let SignedPreKeyBody {
        key_id,
        public_key,
        signature,
    } = signed_pre_key;

    assert_eq!(key_id, 42);
    assert_eq!(
        hex::encode(public_key),
        hex::encode(source_public_key.serialize())
    );
    assert_eq!(&*signature, b"signature");
}
