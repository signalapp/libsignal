//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::device_transfer::{self, KeyFormat};
use libsignal_bridge_macros::*;

// Not used by the Java bridge.
#[allow(unused_imports)]
use crate::support::*;
use crate::*;

#[bridge_fn(node = false)]
fn DeviceTransfer_GeneratePrivateKey() -> Result<Vec<u8>, device_transfer::Error> {
    const DEVICE_TRANSFER_KEY_BITS: usize = 4096;
    device_transfer::create_rsa_private_key(DEVICE_TRANSFER_KEY_BITS, KeyFormat::Pkcs8)
}

// TODO: needed for iOS at the moment, but since it is more generic, could bridge it to JNI as well
#[bridge_fn(node = false, jni = false)]
fn DeviceTransfer_GeneratePrivateKeyWithFormat(
    key_format: u8,
) -> Result<Vec<u8>, device_transfer::Error> {
    const DEVICE_TRANSFER_KEY_BITS: usize = 4096;
    device_transfer::create_rsa_private_key(DEVICE_TRANSFER_KEY_BITS, KeyFormat::from(key_format))
}

#[bridge_fn(node = false)]
fn DeviceTransfer_GenerateCertificate(
    private_key: &[u8],
    name: String,
    days_to_expire: u32,
) -> Result<Vec<u8>, device_transfer::Error> {
    device_transfer::create_self_signed_cert(private_key, &name, days_to_expire)
}
