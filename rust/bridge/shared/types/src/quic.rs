//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use signal_quic::QuicClient;

#[cfg(all(not(target_os = "android"), feature = "jni"))]
use std::collections::HashMap;

#[cfg(all(not(target_os = "android"), feature = "jni"))]
pub struct QuicHeaders(pub HashMap<String, String>);

bridge_as_handle!(QuicClient, mut = true);
