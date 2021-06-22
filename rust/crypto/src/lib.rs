//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]
#![cfg_attr(target_arch = "aarch64", feature(aarch64_target_feature))]
#![deny(clippy::unwrap_used)]

mod error;
mod hash;

mod aes_ctr;
mod aes_gcm;
mod cpuid;
mod ghash;
mod polyval;

pub use {
    aes_ctr::Aes256Ctr32,
    aes_gcm::{Aes256GcmDecryption, Aes256GcmEncryption},
    error::{Error, Result},
    hash::{CryptographicHash, CryptographicMac},
};
