//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod backup;
mod error;
mod hash;

use core::{fmt, str};

pub use backup::*;
pub use error::{Error, Result};
pub use hash::{local_pin_hash, verify_local_pin_hash, PinHash};
use hkdf::Hkdf;
use rand::distributions::Slice;
use rand::Rng;
use sha2::Sha256;

pub const SVR_KEY_LEN: usize = 32;

// The randomly-generated user-memorized entropy backing the "Backup Key"
pub struct AccountEntropyPool {
    // TODO(andrew): Ideally we would swap u8 with std::ascii::char when it stabilizes.
    entropy_pool: [u8; Self::LENGTH],
}

impl AccountEntropyPool {
    const LENGTH: usize = 64;
    const ALPHABET: &'static [u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    pub fn generate(rng: &mut impl Rng) -> AccountEntropyPool {
        let alphabet_dist = Slice::new(Self::ALPHABET).unwrap();
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
        use rand::SeedableRng;

        use crate::{AccountEntropyPool, InvalidAccountEntropyPool};

        fn test_rng(seed: u64) -> impl Rng {
            StdRng::seed_from_u64(seed)
        }

        #[test]
        fn only_alphabet_characters_are_used() {
            let allowed_chars = HashSet::from_iter("abcdefghijklmnopqrstuvwxyz0123456789".chars());

            proptest!(|(seed: u64)| {
                let entropy_pool: String = AccountEntropyPool::generate(&mut test_rng(seed)).to_string();
                let actual_chars = HashSet::<char>::from_iter(entropy_pool.chars());
                let diff = actual_chars.difference(&allowed_chars).collect::<HashSet<_>>();
                assert!(diff.is_empty(), "Disallowed characters in the pool: {:?} from {seed}", diff);
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
}
