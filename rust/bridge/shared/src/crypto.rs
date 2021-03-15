//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::signal_crypto;
use libsignal_bridge_macros::*;
use signal_crypto::*;

use crate::support::*;
use crate::*;

bridge_handle!(CryptographicHash, mut = true, ffi = false, node = false);
bridge_handle!(CryptographicMac, mut = true, ffi = false, node = false);
bridge_handle!(Aes256GcmSiv, clone = false);

#[bridge_fn]
fn Aes256GcmSiv_New(key: &[u8]) -> Result<Aes256GcmSiv> {
    Aes256GcmSiv::new(&key)
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

#[bridge_fn(ffi = false, node = false)]
fn CryptographicHash_New(algo: String) -> Result<CryptographicHash> {
    Ok(CryptographicHash::new(&algo)?)
}

#[bridge_fn_void(ffi = false, node = false)]
fn CryptographicHash_Update(hash: &mut CryptographicHash, input: &[u8]) -> Result<()> {
    hash.update(input)
}

#[bridge_fn_void(ffi = false, node = false)]
fn CryptographicHash_UpdateWithOffset(
    hash: &mut CryptographicHash,
    input: &[u8],
    offset: u32,
    len: u32,
) -> Result<()> {
    let offset = offset as usize;
    let len = len as usize;
    hash.update(&input[offset..(offset + len)])
}

#[bridge_fn_buffer(ffi = false, node = false)]
fn CryptographicHash_Finalize<T: Env>(env: T, hash: &mut CryptographicHash) -> Result<T::Buffer> {
    let digest = hash.finalize()?;
    Ok(env.buffer(digest))
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicMac_New(algo: String, key: &[u8]) -> Result<CryptographicMac> {
    Ok(CryptographicMac::new(&algo, key)?)
}

#[bridge_fn_void(ffi = false, node = false)]
fn CryptographicMac_Update(mac: &mut CryptographicMac, input: &[u8]) -> Result<()> {
    mac.update(input)
}

#[bridge_fn_void(ffi = false, node = false)]
fn CryptographicMac_UpdateWithOffset(
    mac: &mut CryptographicMac,
    input: &[u8],
    offset: u32,
    len: u32,
) -> Result<()> {
    let offset = offset as usize;
    let len = len as usize;
    mac.update(&input[offset..(offset + len)])
}

#[bridge_fn_buffer(ffi = false, node = false)]
fn CryptographicMac_Finalize<T: Env>(env: T, mac: &mut CryptographicMac) -> Result<T::Buffer> {
    let digest = mac.finalize()?;
    Ok(env.buffer(digest))
}
