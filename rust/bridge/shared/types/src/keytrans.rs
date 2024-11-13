//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use libsignal_net::keytrans::{ChatSearchContext, SearchResult};

use crate::*;

bridge_as_handle!(ChatSearchContext, ffi = false, node = false);
bridge_as_handle!(SearchResult, ffi = false, node = false);

type SearchKey = Vec<u8>;
type SerializedMonitorData = Vec<u8>;
pub struct MonitorDataUpdates(pub Vec<(SearchKey, SerializedMonitorData)>);

bridge_as_handle!(MonitorDataUpdates, ffi = false, node = false);
