//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]
#![cfg_attr(target_arch = "aarch64", feature(aarch64_target_feature))]

mod aes;
mod aes_gcm_siv;
mod cpuid;
mod error;
mod polyval;

pub use crate::aes_gcm_siv::Aes256GcmSiv;
pub use crate::error::Error;
