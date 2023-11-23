//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::new_without_default)]

pub use libsignal_protocol_current::{CiphertextMessageType, PreKeyBundle};

pub trait LibSignalProtocolStore {
    fn version(&self) -> &'static str;
    fn create_pre_key_bundle(&mut self) -> PreKeyBundle;
    fn process_pre_key_bundle(&mut self, remote: &str, pre_key_bundle: PreKeyBundle);
    fn encrypt(&mut self, remote: &str, msg: &[u8]) -> (Vec<u8>, CiphertextMessageType);
    fn decrypt(&mut self, remote: &str, msg: &[u8], msg_type: CiphertextMessageType) -> Vec<u8>;
}

mod current;
pub use current::LibSignalProtocolCurrent;

mod v21;
pub use v21::LibSignalProtocolV21;

mod v12;
pub use v12::LibSignalProtocolV12;
