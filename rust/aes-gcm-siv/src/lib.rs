//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![deny(warnings)]
#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]
#![cfg_attr(target_arch = "aarch64", feature(aarch64_target_feature))]

mod aes;
mod aes_gcm_siv;
mod cpuid;
mod error;
mod polyval;

pub use crate::aes_gcm_siv::Aes256GcmSiv;
pub use crate::error::Error;
