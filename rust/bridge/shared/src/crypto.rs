//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::signal_crypto;
use libsignal_bridge_macros::*;
use signal_crypto::*;

use crate::support::*;
use crate::*;

#[derive(Clone)]
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

#[derive(Clone)]
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

bridge_handle!(CryptographicHash, mut = true, ffi = false, node = false);
bridge_handle!(CryptographicMac, mut = true, ffi = false, node = false);
bridge_handle!(Aes256GcmSiv, clone = false);
bridge_handle!(Aes256Ctr32, mut = true, node = false);
bridge_handle!(Aes256GcmEncryption, mut = true, node = false);
bridge_handle!(Aes256GcmDecryption, mut = true, node = false);

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

#[bridge_fn_buffer(node = false)]
fn Aes256GcmEncryption_ComputeTag<T: Env>(
    env: T,
    gcm: &mut Aes256GcmEncryption,
) -> Result<T::Buffer> {
    let tag = gcm.compute_tag()?;
    Ok(env.buffer(tag))
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
