//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
pub fn has_armv8_crypto() -> bool {
    // Require NEON, AES and PMULL
    let hwcap_crypto = (1 << 1) | (1 << 3) | (1 << 4);
    let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
    hwcap & hwcap_crypto == hwcap_crypto
}

#[cfg(all(target_arch = "aarch64", target_os = "ios"))]
pub fn has_armv8_crypto() -> Result<bool> {
    // All 64-bit iOS devices have AES/PMUL support
    true
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_intel_aesni() -> bool {
    is_x86_feature_detected!("aes")
        && is_x86_feature_detected!("pclmulqdq")
        && is_x86_feature_detected!("ssse3")
}
