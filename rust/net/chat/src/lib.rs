//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

pub mod api;
mod logging;
pub mod registration;
pub mod ws;

#[cfg(feature = "grpc")]
pub mod grpc;
