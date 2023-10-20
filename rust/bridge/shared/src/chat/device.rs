//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use signal_chat::Result;
use signal_chat::device::DeviceClient;

use crate::support::*;
use crate::*;

bridge_handle!(DeviceClient, clone = false, mut = true);

#[bridge_fn(ffi = false, node = false)]
pub fn DeviceClient_New(target: String) -> Result<DeviceClient> {
    DeviceClient::new(target)
}

#[bridge_fn(ffi = false, node = false)]
pub fn DeviceClient_GetDevices(
    device_client: &mut DeviceClient,
    request: &[u8],
    authorization: String,
) -> Result<Vec<u8>> {
    device_client.get_devices(request, authorization)
}
