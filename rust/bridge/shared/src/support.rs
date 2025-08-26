//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::bridge_fn;
pub(crate) use libsignal_bridge_types::support::*;

use crate::*;

bridge_handle_fns!(BridgedStringMap);

#[bridge_fn]
fn BridgedStringMap_new(initial_capacity: u32) -> BridgedStringMap {
    BridgedStringMap::with_capacity(initial_capacity as usize)
}

#[bridge_fn]
fn BridgedStringMap_insert(map: &mut BridgedStringMap, key: String, value: String) {
    map.insert(key, value.into());
}
