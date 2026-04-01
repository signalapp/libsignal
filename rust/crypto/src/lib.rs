//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![deny(clippy::unwrap_used)]
#![feature(register_tool)]
#![register_tool(charon)]

mod error;
mod hash;
mod hpke;

mod aes_cbc;
mod aes_ctr;
mod aes_gcm;

pub use aes_cbc::{DecryptionError, EncryptionError, aes_256_cbc_decrypt, aes_256_cbc_encrypt};
pub use aes_ctr::Aes256Ctr32;
pub use aes_gcm::{Aes256GcmDecryption, Aes256GcmEncryption};
pub use error::{Error, Result};
pub use hash::{CryptographicHash, CryptographicMac};
pub use hpke::{HpkeError, SimpleHpkeReceiver, SimpleHpkeSender};

// Workaround for Aeneas bug: trait impl names for ZeroablePrimitive are only
// registered when seen in function bodies. These dummy functions ensure the
// impls for NonZeroU8 and NonZeroU64 (used by DeviceId and E164 in
// libsignal-core) get their names registered.
// See: https://github.com/AeneasVerif/aeneas/issues/XXX
#[cfg(feature = "extraction")]
pub mod _aeneas_workaround {
    pub fn _force_nonzero_u8() -> Option<std::num::NonZeroU8> {
        std::num::NonZeroU8::new(1)
    }
    pub fn _force_nonzero_u64() -> Option<std::num::NonZeroU64> {
        std::num::NonZeroU64::new(1)
    }
}
