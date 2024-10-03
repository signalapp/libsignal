//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod error;
mod hash;

use core::{fmt, str};

pub use error::{Error, Result};
pub use hash::{local_pin_hash, verify_local_pin_hash, PinHash};
use rand::distributions::Slice;
use rand::Rng;

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
}

impl fmt::Display for AccountEntropyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            str::from_utf8(&self.entropy_pool).expect("entropy_pool should only be [a-z0-9]+"),
        )
    }
}

#[cfg(test)]
mod tests {
    mod account_entropy_pool_tests {
        use std::collections::HashSet;

        use proptest::prelude::*;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        use crate::AccountEntropyPool;

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
    }
}
