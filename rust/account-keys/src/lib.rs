//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

mod backup;
mod error;
mod hash;

use core::{fmt, str};

pub use backup::*;
pub use error::{Error, Result};
pub use hash::{PinHash, local_pin_hash, verify_local_pin_hash};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use rand::distr::slice;
use rand::{CryptoRng, Rng};
use sha2::Sha256;

pub const SVR_KEY_LEN: usize = 32;

// The randomly-generated user-memorized entropy backing the "Backup Key"
pub struct AccountEntropyPool {
    // TODO(andrew): Ideally we would swap u8 with std::ascii::char when it stabilizes.
    // No MSRV yet, see: https://github.com/rust-lang/rust/issues/110998
    entropy_pool: [u8; Self::LENGTH],
}

impl AccountEntropyPool {
    const LENGTH: usize = 64;
    const ALPHABET: &'static [u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    pub fn generate(rng: &mut (impl Rng + CryptoRng + ?Sized)) -> AccountEntropyPool {
        let alphabet_dist = slice::Choose::new(Self::ALPHABET).expect("non-empty");
        let entropy_pool: [u8; Self::LENGTH] = std::array::from_fn(|_| *rng.sample(alphabet_dist));
        Self { entropy_pool }
    }

    pub fn derive_svr_key(&self) -> [u8; SVR_KEY_LEN] {
        let mut key = [0; BACKUP_KEY_LEN];
        Hkdf::<Sha256>::new(None, &self.entropy_pool)
            .expand(b"20240801_SIGNAL_SVR_MASTER_KEY", &mut key)
            .expect("valid length");
        key
    }
}

/// An account's SVR key: the 32-byte root from which account-related secrets are derived.
///
/// Signal clients historically call these bytes the "master key"; libsignal calls it the SVR key.
/// The two names refer to the same value. It is *derived* from the [`AccountEntropyPool`] and is
/// stored on the client and in SVR, but is not directly exposed to the user.
///
/// The name "master key" predates the AccountEntropyPool: the key used to be randomly generated and
/// served as the root for a variety of concerns (registration lock, storage service, ...). Now that
/// those keys are derived from the AccountEntropyPool instead, it is no longer a "master" key, so
/// libsignal names it after its remaining role: the key stored in SVR.
///
/// ```text
/// AccountEntropyPool  (64 chars [a-z0-9]; the user-recoverable root)
///        │  HKDF-SHA256(info = "20240801_SIGNAL_SVR_MASTER_KEY")
///        ▼
///     SvrKey  (32 bytes; stored in SVR, protected by the PIN)
///        │  HMAC-SHA256(svrKey, <label>)
///        ├─ "Registration Lock"  → registration lock token
///        └─ (other labels: registration recovery password, storage service key, …)
/// ```
#[derive(Clone)]
pub struct SvrKey([u8; SVR_KEY_LEN]);

impl SvrKey {
    /// Wraps the raw 32-byte SVR key.
    ///
    /// The bytes typically come from [`AccountEntropyPool::derive_svr_key`].
    pub fn new(svr_key: [u8; SVR_KEY_LEN]) -> Self {
        Self(svr_key)
    }

    /// Derives the registration lock token as `HMAC-SHA256(svrKey, "Registration Lock")`.
    ///
    /// This is the raw 32-byte token; the server-facing (legacy REST) representation is this value
    /// hex-encoded, whereas the typed gRPC API sends these raw bytes directly.
    pub fn derive_registration_lock(&self) -> [u8; 32] {
        self.derive(b"Registration Lock")
    }

    /// Derives the password used to recover an account without SMS verification.
    pub fn derive_registration_recovery_password(&self) -> [u8; 32] {
        self.derive(b"Registration Recovery")
    }

    /// Derives the root key used to encrypt data in Storage Service.
    pub fn derive_storage_service_key(&self) -> [u8; 32] {
        self.derive(b"Storage Service Encryption")
    }

    /// Derives the key used to obscure sensitive identifiers in logs.
    pub fn derive_logging_key(&self) -> [u8; 32] {
        self.derive(b"Logging Key")
    }

    fn derive(&self, label: &[u8]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts keys of any length");
        mac.update(label);
        mac.finalize().into_bytes().into()
    }
}

impl fmt::Debug for SvrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the raw key material.
        f.debug_tuple("SvrKey").field(&"_").finish()
    }
}

impl fmt::Display for AccountEntropyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            str::from_utf8(&self.entropy_pool).expect("entropy_pool should only be [a-z0-9]+"),
        )
    }
}

impl fmt::Debug for AccountEntropyPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidAccountEntropyPool {
    WrongLength(usize),
    InvalidCharacter(char),
}

impl fmt::Display for InvalidAccountEntropyPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidAccountEntropyPool::WrongLength(len) => write!(
                f,
                "expected {} ASCII characters, got {} bytes",
                AccountEntropyPool::LENGTH,
                len
            ),
            InvalidAccountEntropyPool::InvalidCharacter(c) => write!(f, "invalid character {c:?}"),
        }
    }
}

impl str::FromStr for AccountEntropyPool {
    type Err = InvalidAccountEntropyPool;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let Ok(entropy_pool) = <[u8; Self::LENGTH]>::try_from(s.as_bytes()) else {
            return Err(InvalidAccountEntropyPool::WrongLength(s.len()));
        };

        // Using is_ascii_digit and is_ascii_lowercase generates more efficient code than
        // ALPHABET.contains.
        if let Some(invalid_pos) = entropy_pool
            .iter()
            .position(|c| !c.is_ascii_digit() && !c.is_ascii_lowercase())
        {
            return Err(InvalidAccountEntropyPool::InvalidCharacter(
                s[invalid_pos..]
                    .chars()
                    .next()
                    .expect("found in byte representation"),
            ));
        }

        Ok(Self { entropy_pool })
    }
}

#[cfg(test)]
mod tests {
    mod account_entropy_pool_tests {
        use std::collections::HashSet;
        use std::str::FromStr as _;

        use assert_matches::assert_matches;
        use proptest::prelude::*;
        use rand::rngs::StdRng;
        use rand::{CryptoRng, SeedableRng as _};

        use crate::{AccountEntropyPool, InvalidAccountEntropyPool};

        fn test_rng(seed: u64) -> impl CryptoRng {
            StdRng::seed_from_u64(seed)
        }

        #[test]
        fn only_alphabet_characters_are_used() {
            let allowed_chars = HashSet::from_iter("abcdefghijklmnopqrstuvwxyz0123456789".chars());

            proptest!(|(seed: u64)| {
                let entropy_pool: String = AccountEntropyPool::generate(&mut test_rng(seed)).to_string();
                let actual_chars = HashSet::<char>::from_iter(entropy_pool.chars());
                let diff = actual_chars.difference(&allowed_chars).collect::<HashSet<_>>();
                assert!(diff.is_empty(), "Disallowed characters in the pool: {diff:?} from {seed}");
            });
        }

        #[test]
        fn uniqueness() {
            let mut set = HashSet::new();
            const NUM_ITERATIONS: usize = 1_000;
            let mut rng = test_rng(0);

            for _ in 0..NUM_ITERATIONS {
                let entropy_pool: String = AccountEntropyPool::generate(&mut rng).to_string();
                assert!(
                    set.insert(entropy_pool.clone()),
                    "{entropy_pool} has already been seen."
                );
            }
        }

        #[test]
        fn parse() {
            assert_matches!(
                AccountEntropyPool::from_str(std::str::from_utf8(&[b'm'; 64]).expect("ascii")),
                Ok(AccountEntropyPool { entropy_pool }) if entropy_pool == [b'm'; AccountEntropyPool::LENGTH]
            );
            assert_matches!(
                AccountEntropyPool::from_str("abc"),
                Err(InvalidAccountEntropyPool::WrongLength(3))
            );
            assert_matches!(
                AccountEntropyPool::from_str(std::str::from_utf8(&[b' '; 64]).expect("ascii")),
                Err(InvalidAccountEntropyPool::InvalidCharacter(' '))
            );
        }
    }

    mod svr_key_tests {
        use const_str::hex;

        use crate::SvrKey;

        // These known answers were taken from iOS' MasterKeyTest.testDerivedKeys.
        // See: https://github.com/signalapp/Signal-iOS/blob/265ee500/SignalServiceKit/tests/Account/MasterKeyTest.swift#L54

        #[test]
        fn derive_registration_lock_known_answer() {
            // Cross-checked against the Android/iOS clients' MasterKey.deriveRegistrationLock():
            // an SVR key of 32 `0x2a` bytes derives this registration lock token.
            let svr_key = SvrKey::new([0x2a; 32]);
            assert_eq!(
                svr_key.derive_registration_lock(),
                hex!("3a40e25812e6c20cca76a602451dd2bc7484553514438cade320c2aef54e10d1")
            );
        }

        #[test]
        fn derive_registration_recovery_password_known_answer() {
            let svr_key = SvrKey::new([0x2a; 32]);
            assert_eq!(
                svr_key.derive_registration_recovery_password(),
                hex!("91f959cfee39676dedd028bc8bbbd1e91ffa6a42c57754d095fe8abe7f0d4f56")
            );
        }

        #[test]
        fn derive_storage_service_key_known_answer() {
            let svr_key = SvrKey::new([0x2a; 32]);
            assert_eq!(
                svr_key.derive_storage_service_key(),
                hex!("3f31b618172a9f8ad45e290788e6176736e6161d4ea0e8050f8553521f59c200")
            );
        }

        #[test]
        fn derive_logging_key_known_answer() {
            let svr_key = SvrKey::new([0x2a; 32]);
            assert_eq!(
                svr_key.derive_logging_key(),
                hex!("cd2a39f4857de4df3fe793d1de061bfa3dd63533c0a4ef79b3fa3eba2bf96e62")
            );
        }

        #[test]
        fn debug_does_not_leak_key_material() {
            let svr_key = SvrKey::new([0x2a; 32]);
            assert_eq!(format!("{svr_key:?}"), r#"SvrKey("_")"#);
        }
    }
}
