//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::aes_gcm_siv;
use aes_gcm_siv::error::Result;
use aes_gcm_siv::Aes256GcmSiv;
use libsignal_bridge_macros::*;

use crate::support::*;
use crate::*;

bridge_handle!(Aes256GcmSiv, clone = false);

#[bridge_fn]
fn Aes256GcmSiv_New(key: &[u8]) -> Result<Aes256GcmSiv> {
    aes_gcm_siv::Aes256GcmSiv::new(&key)
}

#[bridge_fn_buffer]
fn Aes256GcmSiv_Encrypt<T: Env>(
    env: T,
    aes_gcm_siv: &Aes256GcmSiv,
    ptext: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<T::Buffer> {
    let mut buf = Vec::with_capacity(ptext.len() + 16);
    buf.extend_from_slice(ptext);

    let gcm_tag = aes_gcm_siv.encrypt(&mut buf, &nonce, &associated_data)?;
    buf.extend_from_slice(&gcm_tag);

    Ok(env.buffer(buf))
}

#[bridge_fn_buffer]
fn Aes256GcmSiv_Decrypt<T: Env>(
    env: T,
    aes_gcm_siv: &Aes256GcmSiv,
    ctext: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<T::Buffer> {
    let mut buf = ctext.to_vec();
    aes_gcm_siv.decrypt_with_appended_tag(&mut buf, &nonce, &associated_data)?;
    Ok(env.buffer(buf))
}
