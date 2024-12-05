//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use libsignal_net::keytrans::SearchResult;

use crate::*;

bridge_as_handle!(SearchResult, ffi = false, node = false);
