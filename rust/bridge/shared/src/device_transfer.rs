//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::device_transfer;
use libsignal_bridge_macros::*;

use crate::support::*;
use crate::*;

#[bridge_fn_buffer(node = false)]
fn DeviceTransfer_GeneratePrivateKey<T: Env>(env: T) -> Result<T::Buffer, device_transfer::Error> {
    const DEVICE_TRANSFER_KEY_BITS: usize = 4096;

    let buf = device_transfer::create_rsa_private_key(DEVICE_TRANSFER_KEY_BITS)?;
    Ok(env.buffer(buf))
}

#[bridge_fn_buffer(node = false)]
fn DeviceTransfer_GenerateCertificate<T: Env>(
    env: T,
    private_key: &[u8],
    name: String,
    days_to_expire: u32,
) -> Result<T::Buffer, device_transfer::Error> {
    let buf = device_transfer::create_self_signed_cert(private_key, &name, days_to_expire)?;
    Ok(env.buffer(buf))
}
