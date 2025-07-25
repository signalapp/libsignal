//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_account_keys::BackupKey;
use libsignal_net::svrb as svrb_impl;
use libsignal_net::svrb::BackupResponse;
// Re-export the error type for FFI implementations
pub use svrb_impl::Error;

use crate::net::Environment;
use crate::*;

bridge_as_handle!(BackupResponse);

pub struct StoreArgs {
    pub backup_key: BackupKey,
    pub previous_metadata: Box<[u8]>,
    pub environment: Environment,
}

bridge_as_handle!(StoreArgs);
