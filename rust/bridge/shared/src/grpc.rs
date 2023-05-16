//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use signal_grpc::{GrpcClient, GrpcReplyListener, Result};

use crate::support::*;
use crate::*;

use std::collections::HashMap;

#[cfg(all(feature = "jni"))]
pub struct GrpcHeaders(pub HashMap<String, Vec<String>>);

bridge_handle!(GrpcClient, clone = false, mut = true);

#[bridge_fn(ffi = false, node = false)]
pub fn GrpcClient_New(target: String) -> Result<GrpcClient> {
    GrpcClient::new(target)
}

#[bridge_fn_void(ffi = false, node = false)]
pub fn GrpcClient_OpenStream(grpc_client: &mut GrpcClient, uri: String, headers: GrpcHeaders, listener: &mut dyn GrpcReplyListener) -> Result<()> {
    grpc_client.open_stream(uri, headers.0, listener)
}

#[bridge_fn_void(ffi = false, node = false)]
pub fn GrpcClient_SendMessage(grpc_client: &mut GrpcClient, method: String, url_fragment: String, body: &[u8], headers: GrpcHeaders) -> Result<()> {
    grpc_client.send_message(method, url_fragment, body, headers.0)
}
