//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hex_literal::hex;
use libsignal_bridge_macros::*;
use libsignal_core::Aci;
use libsignal_keytrans::{LocalStateUpdate, MonitoringData, TreeHead};
use libsignal_net::keytrans::{SearchKey, SearchResult};
use libsignal_protocol::IdentityKey;
use uuid::Uuid;

use crate::*;

#[cfg(feature = "jni")]
const TEST_ACI: Uuid = uuid::uuid!("90c979fd-eab4-4a08-b6da-69dedeab9b29");
#[cfg(feature = "jni")]
const TEST_ACI_IDENTITY_KEY_BYTES: &[u8] =
    &hex!("05d0e797ec91a4bce0e88959c419e96eb4fdabbb3dc688965584c966dc24195609");

#[bridge_fn(node = false, ffi = false)]
fn TESTING_ChatSearchResult() -> SearchResult {
    let aci = Aci::from(TEST_ACI);
    SearchResult {
        aci_identity_key: IdentityKey::decode(TEST_ACI_IDENTITY_KEY_BYTES)
            .expect("valid serialized key"),
        aci_for_e164: Some(aci),
        aci_for_username_hash: Some(aci),
        state_update: Some(LocalStateUpdate {
            tree_head: TreeHead {
                tree_size: 42,
                timestamp: 42424242,
                signature: vec![1, 2, 3],
            },
            tree_root: [42; 32],
            monitors: vec![(
                aci.as_search_key(),
                MonitoringData {
                    index: [42; 32],
                    pos: 0,
                    ptrs: Default::default(),
                    owned: false,
                },
            )],
        }),
    }
}
