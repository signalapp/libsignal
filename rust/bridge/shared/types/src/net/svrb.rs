//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::svrb as svrb_impl;
// Re-export the error type for FFI implementations
pub use svrb_impl::Error;

use crate::*;

// Wrapper types for the SVR backup API
#[derive(derive_more::From)]
pub struct PreparedSvrBContext(pub svrb_impl::PrepareBackupResponse);

bridge_as_handle!(PreparedSvrBContext);
