//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::signal_crypto;
use aes_gcm_siv::aead::generic_array::typenum::Unsigned;
use aes_gcm_siv::{AeadCore, AeadInPlace, KeyInit};
use libsignal_bridge_macros::*;
use libsignal_bridge_types::crypto::{Aes256GcmDecryption, Aes256GcmEncryption, Aes256GcmSiv};
use signal_crypto::{Aes256Ctr32, CryptographicHash, CryptographicMac, Error, Result};

use crate::support::*;
use crate::*;

bridge_handle_fns!(CryptographicHash, ffi = false, node = false);
bridge_handle_fns!(CryptographicMac, ffi = false, node = false);
bridge_handle_fns!(Aes256GcmSiv, clone = false);
bridge_handle_fns!(Aes256Ctr32, clone = false, node = false);
bridge_handle_fns!(Aes256GcmEncryption, clone = false, node = false);
bridge_handle_fns!(Aes256GcmDecryption, clone = false, node = false);

#[bridge_fn(node = false)]
fn Aes256Ctr32_New(key: &[u8], nonce: &[u8], initial_ctr: u32) -> Result<Aes256Ctr32> {
    Aes256Ctr32::from_key(key, nonce, initial_ctr)
}

#[bridge_fn(node = false)]
fn Aes256Ctr32_Process(ctr: &mut Aes256Ctr32, data: &mut [u8], offset: u32, length: u32) {
    let offset = offset as usize;
    let length = length as usize;
    ctr.process(&mut data[offset..offset + length]);
}

#[bridge_fn(node = false)]
fn Aes256GcmEncryption_New(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<Aes256GcmEncryption> {
    Aes256GcmEncryption::new(key, nonce, associated_data)
}

#[bridge_fn(node = false)]
fn Aes256GcmEncryption_Update(
    gcm: &mut Aes256GcmEncryption,
    data: &mut [u8],
    offset: u32,
    length: u32,
) {
    let offset = offset as usize;
    let length = length as usize;
    gcm.encrypt(&mut data[offset..offset + length]);
}

#[bridge_fn(node = false)]
fn Aes256GcmEncryption_ComputeTag(gcm: &mut Aes256GcmEncryption) -> Vec<u8> {
    gcm.compute_tag()
}

#[bridge_fn(node = false)]
fn Aes256GcmDecryption_New(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<Aes256GcmDecryption> {
    Aes256GcmDecryption::new(key, nonce, associated_data)
}

#[bridge_fn(node = false)]
fn Aes256GcmDecryption_Update(
    gcm: &mut Aes256GcmDecryption,
    data: &mut [u8],
    offset: u32,
    length: u32,
) {
    let offset = offset as usize;
    let length = length as usize;
    gcm.decrypt(&mut data[offset..offset + length]);
}

#[bridge_fn(node = false)]
fn Aes256GcmDecryption_VerifyTag(gcm: &mut Aes256GcmDecryption, tag: &[u8]) -> Result<bool> {
    gcm.verify_tag(tag)
}

#[bridge_fn]
fn Aes256GcmSiv_New(key: &[u8]) -> Result<Aes256GcmSiv> {
    Ok(Aes256GcmSiv(
        aes_gcm_siv::Aes256GcmSiv::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?,
    ))
}

#[bridge_fn]
fn Aes256GcmSiv_Encrypt(
    aes_gcm_siv_obj: &Aes256GcmSiv,
    ptext: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != <aes_gcm_siv::Aes256GcmSiv as AeadCore>::NonceSize::USIZE {
        return Err(Error::InvalidNonceSize);
    }
    let nonce: &aes_gcm_siv::Nonce = nonce.into();

    let mut buf =
        Vec::with_capacity(ptext.len() + <aes_gcm_siv::Aes256GcmSiv as AeadCore>::TagSize::USIZE);
    buf.extend_from_slice(ptext);

    aes_gcm_siv_obj
        .0
        .encrypt_in_place(nonce, associated_data, &mut buf)
        .expect("cannot run out of capacity in a Vec");

    Ok(buf)
}

#[bridge_fn]
fn Aes256GcmSiv_Decrypt(
    aes_gcm_siv: &Aes256GcmSiv,
    ctext: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != <aes_gcm_siv::Aes256GcmSiv as AeadCore>::NonceSize::USIZE {
        return Err(Error::InvalidNonceSize);
    }
    let nonce: &aes_gcm_siv::Nonce = nonce.into();

    let mut buf = ctext.to_vec();
    aes_gcm_siv
        .0
        .decrypt_in_place(nonce, associated_data, &mut buf)
        .map_err(|_| Error::InvalidTag)?;
    Ok(buf)
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicHash_New(algo: String) -> Result<CryptographicHash> {
    CryptographicHash::new(&algo)
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicHash_Update(hash: &mut CryptographicHash, input: &[u8]) {
    hash.update(input)
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicHash_UpdateWithOffset(
    hash: &mut CryptographicHash,
    input: &[u8],
    offset: u32,
    len: u32,
) {
    let offset = offset as usize;
    let len = len as usize;
    hash.update(&input[offset..(offset + len)])
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicHash_Finalize(hash: &mut CryptographicHash) -> Vec<u8> {
    hash.finalize()
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicMac_New(algo: String, key: &[u8]) -> Result<CryptographicMac> {
    CryptographicMac::new(&algo, key)
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicMac_Update(mac: &mut CryptographicMac, input: &[u8]) {
    mac.update(input)
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicMac_UpdateWithOffset(
    mac: &mut CryptographicMac,
    input: &[u8],
    offset: u32,
    len: u32,
) {
    let offset = offset as usize;
    let len = len as usize;
    mac.update(&input[offset..(offset + len)])
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicMac_Finalize(mac: &mut CryptographicMac) -> Vec<u8> {
    mac.finalize()
}
