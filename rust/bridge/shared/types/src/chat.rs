//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use signal_chat::device::DeviceClient;
use signal_chat::profile::ProfileClient;

bridge_as_handle!(DeviceClient, mut = true);
bridge_as_handle!(ProfileClient, mut = true);
