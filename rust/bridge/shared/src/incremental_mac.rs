//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;

use hmac::{Hmac, NewMac};
use sha2::digest::FixedOutput;
use typenum::Unsigned;

use libsignal_bridge_macros::*;
use libsignal_protocol::incremental_mac::{calculate_chunk_size, Incremental, Validating};

use crate::support::*;
use crate::*;

type Digest = sha2::Sha256;

#[bridge_fn]
pub fn IncrementalMac_CalculateChunkSize(data_size: u32) -> u32 {
    calculate_chunk_size::<Digest>(data_size as usize)
        .try_into()
        .expect("Chunk size cannot be represented")
}

#[derive(Clone)]
pub struct IncrementalMac(Option<Incremental<Hmac<Digest>>>);

bridge_handle!(IncrementalMac, clone = false, mut = true);

#[bridge_fn]
pub fn IncrementalMac_Initialize(key: &[u8], chunk_size: u32) -> IncrementalMac {
    let hmac =
        Hmac::<Digest>::new_from_slice(key).expect("Should be able to create a new HMAC instance");
    IncrementalMac(Some(Incremental::new(hmac, chunk_size as usize)))
}

#[bridge_fn]
pub fn IncrementalMac_Update(
    mac: &mut IncrementalMac,
    bytes: &[u8],
    offset: u32,
    length: u32,
) -> Vec<u8> {
    let offset = offset as usize;
    let length = length as usize;
    mac.0
        .as_mut()
        .expect("MAC used after finalize")
        .update(&bytes[offset..offset + length])
        .flat_map(|out| -> [u8; 32] { out.into_bytes().into() })
        .collect()
}

#[bridge_fn]
pub fn IncrementalMac_Finalize(mac: &mut IncrementalMac) -> Vec<u8> {
    mac.0
        .take()
        .expect("MAC used after finalize")
        .finalize()
        .into_bytes()
        .to_vec()
}

#[derive(Clone)]
pub struct ValidatingMac(Option<Validating<Hmac<Digest>>>);

bridge_handle!(ValidatingMac, clone = false, mut = true);

#[bridge_fn]
pub fn ValidatingMac_Initialize(key: &[u8], chunk_size: u32, digests: &[u8]) -> ValidatingMac {
    let hmac =
        Hmac::<Digest>::new_from_slice(key).expect("Should be able to create a new HMAC instance");
    let incremental = Incremental::new(hmac, chunk_size as usize);
    let macs = digests.chunks(<Digest as FixedOutput>::OutputSize::USIZE);
    ValidatingMac(Some(incremental.validating(macs)))
}

#[bridge_fn]
pub fn ValidatingMac_Update(
    mac: &mut ValidatingMac,
    bytes: &[u8],
    offset: u32,
    length: u32,
) -> bool {
    let offset = offset as usize;
    let length = length as usize;
    mac.0
        .as_mut()
        .expect("MAC used after finalize")
        .update(&bytes[offset..][..length])
        .is_ok()
}

#[bridge_fn]
pub fn ValidatingMac_Finalize(mac: &mut ValidatingMac) -> bool {
    mac.0
        .take()
        .expect("MAC used after finalize")
        .finalize()
        .is_ok()
}

impl Drop for IncrementalMac {
    fn drop(&mut self) {
        if self.0.is_some() {
            report_unexpected_drop()
        }
    }
}

impl Drop for ValidatingMac {
    fn drop(&mut self) {
        if self.0.is_some() {
            report_unexpected_drop()
        }
    }
}

static UNEXPECTED_DROP_MESSAGE: &str = "MAC is dropped without calling finalize";

fn report_unexpected_drop() {
    if cfg!(test) {
        panic!("{}", UNEXPECTED_DROP_MESSAGE);
    } else {
        log::warn!("{}", UNEXPECTED_DROP_MESSAGE);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn drop_without_finalize() {
        let incremental = IncrementalMac_Initialize(&[], 32);
        std::mem::drop(incremental);
    }

    #[test]
    fn drop_with_finalize() {
        let mut incremental = IncrementalMac_Initialize(&[], 32);
        IncrementalMac_Finalize(&mut incremental);
        std::mem::drop(incremental);
    }
}
