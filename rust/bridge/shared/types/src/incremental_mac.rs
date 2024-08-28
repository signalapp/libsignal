//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::Hmac;
use libsignal_protocol::incremental_mac::{Incremental, Validating};

use crate::*;

pub type Digest = sha2::Sha256;

#[derive(Clone)]
pub struct IncrementalMac(pub Option<Incremental<Hmac<Digest>>>);

bridge_as_handle!(IncrementalMac, mut = true);

#[derive(Clone)]
pub struct ValidatingMac(pub Option<Validating<Hmac<Digest>>>);

bridge_as_handle!(ValidatingMac, mut = true);

impl Drop for IncrementalMac {
    fn drop(&mut self) {
        if self.0.is_some() {
            log::warn!("{}", UNEXPECTED_DROP_MESSAGE);
        }
    }
}

pub static UNEXPECTED_DROP_MESSAGE: &str = "MAC is dropped without calling finalize";
