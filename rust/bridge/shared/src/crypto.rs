//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::signal_crypto;
use libsignal_bridge_macros::*;
use signal_crypto::*;

use aes_gcm_siv::aead::generic_array::typenum::Unsigned;
use aes_gcm_siv::aead::{AeadCore, AeadInPlace, NewAead};

use crate::support::*;
use crate::*;

pub struct Aes256GcmEncryption {
    gcm: Option<signal_crypto::Aes256GcmEncryption>,
}

impl Aes256GcmEncryption {
    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let gcm = signal_crypto::Aes256GcmEncryption::new(key, nonce, associated_data)?;
        Ok(Self { gcm: Some(gcm) })
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        match &mut self.gcm {
            Some(gcm) => gcm.encrypt(buf),
            None => Err(Error::InvalidState),
        }
    }

    pub fn compute_tag(&mut self) -> Result<Vec<u8>> {
        if self.gcm.is_none() {
            return Err(Error::InvalidState);
        }

        let gcm = self.gcm.take().expect("Validated to be Some");

        Ok(gcm.compute_tag()?.to_vec())
    }
}

pub struct Aes256GcmDecryption {
    gcm: Option<signal_crypto::Aes256GcmDecryption>,
}

impl Aes256GcmDecryption {
    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let gcm = signal_crypto::Aes256GcmDecryption::new(key, nonce, associated_data)?;
        Ok(Self { gcm: Some(gcm) })
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        match &mut self.gcm {
            Some(gcm) => gcm.decrypt(buf),
            None => Err(Error::InvalidState),
        }
    }

    pub fn verify_tag(&mut self, tag: &[u8]) -> Result<bool> {
        if self.gcm.is_none() {
            return Err(Error::InvalidState);
        }

        let gcm = self.gcm.take().expect("Validated to be Some");
        match gcm.verify_tag(tag) {
            Ok(()) => Ok(true),
            Err(Error::InvalidTag) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

// Explicit wrapper for cbindgen purposes.
pub struct Aes256GcmSiv(aes_gcm_siv::Aes256GcmSiv);

bridge_handle!(CryptographicHash, mut = true, ffi = false, node = false);
bridge_handle!(CryptographicMac, mut = true, ffi = false, node = false);
bridge_handle!(Aes256GcmSiv, clone = false);
bridge_handle!(Aes256Ctr32, clone = false, mut = true, node = false);
bridge_handle!(Aes256GcmEncryption, clone = false, mut = true, node = false);
bridge_handle!(Aes256GcmDecryption, clone = false, mut = true, node = false);

#[bridge_fn(node = false)]
fn Aes256Ctr32_New(key: &[u8], nonce: &[u8], initial_ctr: u32) -> Result<Aes256Ctr32> {
    Aes256Ctr32::from_key(key, nonce, initial_ctr)
}

#[bridge_fn_void(node = false)]
fn Aes256Ctr32_Process(
    ctr: &mut Aes256Ctr32,
    data: &mut [u8],
    offset: u32,
    length: u32,
) -> Result<()> {
    let offset = offset as usize;
    let length = length as usize;
    ctr.process(&mut data[offset..offset + length])?;
    Ok(())
}

#[bridge_fn(node = false)]
fn Aes256GcmEncryption_New(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
) -> Result<Aes256GcmEncryption> {
    Aes256GcmEncryption::new(key, nonce, associated_data)
}

#[bridge_fn_void(node = false)]
fn Aes256GcmEncryption_Update(
    gcm: &mut Aes256GcmEncryption,
    data: &mut [u8],
    offset: u32,
    length: u32,
) -> Result<()> {
    let offset = offset as usize;
    let length = length as usize;
    gcm.encrypt(&mut data[offset..offset + length])?;
    Ok(())
}

#[bridge_fn(node = false)]
fn Aes256GcmEncryption_ComputeTag(gcm: &mut Aes256GcmEncryption) -> Result<Vec<u8>> {
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

#[bridge_fn_void(node = false)]
fn Aes256GcmDecryption_Update(
    gcm: &mut Aes256GcmDecryption,
    data: &mut [u8],
    offset: u32,
    length: u32,
) -> Result<()> {
    let offset = offset as usize;
    let length = length as usize;
    gcm.decrypt(&mut data[offset..offset + length])?;
    Ok(())
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

#[bridge_fn(ffi = false, node = false)]
fn CryptographicHash_Finalize(hash: &mut CryptographicHash) -> Result<Vec<u8>> {
    hash.finalize()
}

#[bridge_fn(ffi = false, node = false)]
fn CryptographicMac_New(algo: String, key: &[u8]) -> Result<CryptographicMac> {
    CryptographicMac::new(&algo, key)
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

#[bridge_fn(ffi = false, node = false)]
fn CryptographicMac_Finalize(mac: &mut CryptographicMac) -> Result<Vec<u8>> {
    mac.finalize()
}
