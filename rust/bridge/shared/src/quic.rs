//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_bridge_types::quic::QuicHeaders;
use signal_quic::{QuicClient, QuicCallbackListener, Result};

use crate::support::*;
use crate::*;

bridge_handle_fns!(QuicClient, clone = false);

#[bridge_fn(ffi = false, node = false)]
pub fn QuicClient_New(target: String) -> Result<QuicClient> {
    QuicClient::new(target)
}

#[bridge_fn(ffi = false, node = false)]
pub fn QuicClient_SendMessage(quic_client: &mut QuicClient, data: &[u8]) -> Result<Vec<u8>> {
    quic_client.send_message(data)
}

#[bridge_fn(ffi = false, node = false)]
pub fn QuicClient_OpenControlledStream(quic_client: &mut QuicClient, base_url: String, headers: QuicHeaders, listener: &mut dyn QuicCallbackListener) -> Result<()> {
    quic_client.open_controlled_stream(base_url, headers.0, listener)
}

#[bridge_fn(ffi = false, node = false)]
pub fn QuicClient_WriteMessageOnStream(quic_client: &mut QuicClient, payload: &[u8]) -> Result<()> {
    quic_client.write_message_on_stream(payload)
}
