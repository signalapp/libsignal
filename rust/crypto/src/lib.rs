//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]
#![cfg_attr(target_arch = "aarch64", feature(aarch64_target_feature))]
#![deny(clippy::unwrap_used)]

mod error;
mod hash;

mod aes;
mod aes_gcm_siv;
mod cpuid;
mod polyval;

pub use {
    aes_gcm_siv::Aes256GcmSiv,
    error::{Error, Result},
    hash::{CryptographicHash, CryptographicMac},
};
