//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::num::{NonZeroU64, ParseIntError};
use std::str::FromStr;

#[derive(Copy, Clone, Debug, PartialEq, Eq, derive_more::Into)]
pub struct E164(NonZeroU64);

impl E164 {
    pub const fn new(number: NonZeroU64) -> Self {
        Self(number)
    }

    pub fn to_be_bytes(&self) -> [u8; std::mem::size_of::<u64>()] {
        self.0.get().to_be_bytes()
    }

    pub fn from_be_bytes(bytes: [u8; std::mem::size_of::<u64>()]) -> Option<Self> {
        NonZeroU64::new(u64::from_be_bytes(bytes)).map(Self)
    }
}

impl FromStr for E164 {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix('+').unwrap_or(s);
        NonZeroU64::from_str(s).map(Self)
    }
}

impl Display for E164 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "+{}", self.0)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use assert_matches::assert_matches;
    use proptest::{prop_compose, proptest};

    use super::E164;

    prop_compose! {
        fn gen_e164()(num in 18005550101_u64..=18995550199) -> E164 {
            E164::new(num.try_into().expect("non zero value"))
        }
    }

    #[test]
    fn round_trip_through_bytes() {
        proptest!(|(e164 in gen_e164())| {
            assert_matches!(E164::from_be_bytes(e164.to_be_bytes()), Some(actual) => assert_eq!(actual, e164));
        });
    }

    #[test]
    fn round_trip_through_string() {
        proptest!(|(e164 in gen_e164(), strip_prefix: bool)| {
            let mut repr = e164.to_string();
            if strip_prefix {
                repr.remove(0);
            }
            assert_matches!(E164::from_str(&repr), Ok(actual) => assert_eq!(actual, e164));
        });
    }
}
