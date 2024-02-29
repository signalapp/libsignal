//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use signal_chat::Result;
use signal_chat::profile::ProfileClient;

use crate::support::*;
use crate::*;

bridge_handle!(ProfileClient, clone = false, mut = true);

#[bridge_fn(ffi = false, node = false)]
pub fn ProfileClient_New(target: String) -> Result<ProfileClient> {
    ProfileClient::new(target)
}

#[bridge_fn(ffi = false, node = false)]
pub fn ProfileClient_GetVersionedProfile(
    profile_client: &mut ProfileClient,
    request: &[u8],
) -> Result<Vec<u8>> {
    profile_client.get_versioned_profile(request)
}
