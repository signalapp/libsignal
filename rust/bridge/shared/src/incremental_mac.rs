//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crypto_common::KeyInit;
use hmac::digest::typenum::Unsigned;
use hmac::digest::{crypto_common, OutputSizeUser};
use hmac::Hmac;
use libsignal_bridge_macros::*;
use libsignal_bridge_types::incremental_mac::*;
use libsignal_protocol::incremental_mac::{calculate_chunk_size, Incremental};

use crate::support::*;
use crate::*;

bridge_handle_fns!(IncrementalMac, clone = false);

#[bridge_fn]
pub fn IncrementalMac_CalculateChunkSize(data_size: u32) -> u32 {
    calculate_chunk_size::<Digest>(data_size as usize)
        .try_into()
        .expect("Chunk size cannot be represented")
}

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
        .flat_map(|out| -> [u8; 32] { out.into() })
        .collect()
}

#[bridge_fn]
pub fn IncrementalMac_Finalize(mac: &mut IncrementalMac) -> Vec<u8> {
    mac.0
        .take()
        .expect("MAC used after finalize")
        .finalize()
        .as_slice()
        .to_vec()
}

bridge_handle_fns!(ValidatingMac, clone = false);

#[bridge_fn]
pub fn ValidatingMac_Initialize(key: &[u8], chunk_size: u32, digests: &[u8]) -> ValidatingMac {
    let hmac =
        Hmac::<Digest>::new_from_slice(key).expect("Should be able to create a new HMAC instance");
    let incremental = Incremental::new(hmac, chunk_size as usize);
    let macs = digests.chunks(<Digest as OutputSizeUser>::OutputSize::USIZE);
    ValidatingMac(Some(incremental.validating(macs)))
}

#[bridge_fn]
pub fn ValidatingMac_Update(
    mac: &mut ValidatingMac,
    bytes: &[u8],
    offset: u32,
    length: u32,
) -> i32 {
    let offset = offset as usize;
    let length = length as usize;
    mac.0
        .as_mut()
        .expect("MAC used after finalize")
        .update(&bytes[offset..][..length])
        .ok()
        .and_then(|n| n.try_into().ok())
        .unwrap_or(-1)
}

#[bridge_fn]
pub fn ValidatingMac_Finalize(mac: &mut ValidatingMac) -> i32 {
    mac.0
        .take()
        .expect("MAC used after finalize")
        .finalize()
        .ok()
        .and_then(|n| n.try_into().ok())
        .unwrap_or(-1)
}

#[cfg(test)]
mod test {
    use super::*;

    fn find_drop_log<'a>(
        logs: impl IntoIterator<Item = &'a testing_logger::CapturedLog>,
    ) -> Option<&'a testing_logger::CapturedLog> {
        logs.into_iter()
            .find(|log| log.body.contains(UNEXPECTED_DROP_MESSAGE))
    }

    #[test]
    fn drop_without_finalize() {
        testing_logger::setup();
        let incremental = IncrementalMac_Initialize(&[], 32);
        std::mem::drop(incremental);
        testing_logger::validate(|captured_logs| {
            assert!(find_drop_log(captured_logs).is_some());
        })
    }

    #[test]
    fn drop_with_finalize() {
        testing_logger::setup();
        let mut incremental = IncrementalMac_Initialize(&[], 32);
        IncrementalMac_Finalize(&mut incremental);
        std::mem::drop(incremental);
        testing_logger::validate(|captured_logs| {
            assert!(find_drop_log(captured_logs).is_none());
        })
    }
}
