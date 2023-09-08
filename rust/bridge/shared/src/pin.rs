//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;

use crate::support::*;
use crate::*;
use ::attest::svr2::lookup_groupid;
use ::signal_pin::{local_pin_hash, verify_local_pin_hash, PinHash, Result};
use signal_pin::Error;

bridge_handle!(PinHash, node = false);

#[bridge_fn(node = false)]
pub fn PinHash_EncryptionKey(ph: &PinHash) -> [u8; 32] {
    ph.encryption_key
}

#[bridge_fn(node = false)]
pub fn PinHash_AccessKey(ph: &PinHash) -> [u8; 32] {
    ph.access_key
}

#[bridge_fn(node = false)]
pub fn PinHash_FromSalt(pin: &[u8], salt: &[u8; 32]) -> Result<PinHash> {
    PinHash::create(pin, salt)
}

#[bridge_fn(node = false)]
pub fn PinHash_FromUsernameMrenclave(
    pin: &[u8],
    username: String,
    mrenclave: &[u8],
) -> Result<PinHash> {
    PinHash::create(
        pin,
        &PinHash::make_salt(
            &username,
            lookup_groupid(mrenclave).ok_or(Error::MrenclaveLookupError)?,
        ),
    )
}

#[bridge_fn(node = false)]
pub fn Pin_LocalHash(pin: &[u8]) -> Result<String> {
    local_pin_hash(pin)
}

#[bridge_fn(node = false)]
pub fn Pin_VerifyLocalHash(encoded_hash: String, pin: &[u8]) -> Result<bool> {
    verify_local_pin_hash(&encoded_hash, pin)
}
