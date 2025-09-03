//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![deny(clippy::unwrap_used)]

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
