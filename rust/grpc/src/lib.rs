//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod client;
mod error;
mod proto;
mod traits;

pub use client::{GrpcClient, GrpcReply, SignalRpcReplyListener};
pub use error::{Error, Result};
pub use proto::proxy::SignalRpcMessage;
pub use proto::signal::common::ServiceIdentifier;
pub use proto::signal::profile::{GetVersionedProfileRequest, GetVersionedProfileResponse};
pub use traits::GrpcReplyListener;
