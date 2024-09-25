//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::Add;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(SystemTime);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(std::time::Duration);

impl Timestamp {
    const EXPECTED_RANGE_MS: std::ops::Range<u64> =
        // 2000-01-01 - UNIX_EPOCH
        946_684_800_000..
        // 2100-01-01 - UNIX_EPOCH
        4_102_444_800_000;

    #[track_caller]
    pub fn from_millis(since_epoch: u64, context: &'static str) -> Self {
        if since_epoch < Self::EXPECTED_RANGE_MS.start {
            log::warn!("timestamp {context} value {since_epoch} is far in the past");
        } else if since_epoch > Self::EXPECTED_RANGE_MS.end {
            log::warn!("timestamp {context} value {since_epoch} is far in the future");
        }
        Self(UNIX_EPOCH + std::time::Duration::from_millis(since_epoch))
    }

    pub(super) fn into_inner(self) -> SystemTime {
        self.0
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let offset = self
            .0
            .duration_since(UNIX_EPOCH)
            .expect("should not be possible to construct a Timestamp older than UNIX_EPOCH");
        serde::Serialize::serialize(&Duration(offset), serializer)
    }
}

impl Duration {
    pub(super) const ZERO: Self = Self(std::time::Duration::ZERO);

    pub(super) const fn from_millis(millis: u64) -> Self {
        Self(std::time::Duration::from_millis(millis))
    }

    pub(super) const fn from_hours(hours: u64) -> Self {
        // std::time::Duration::from_hours isn't stable yet, but it's the same as this.
        Self(std::time::Duration::from_secs(60 * 60 * hours))
    }
}

impl serde::Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        assert!(
            self.0.as_millis() * 1_000_000 == self.0.as_nanos(),
            "should not be possible to construct a Duration with sub-millisecond precision ({:?})",
            self.0
        );
        self.0.as_millis().serialize(serializer)
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Self::Output {
        Timestamp(self.0 + rhs.0)
    }
}

#[cfg(test)]
pub(super) mod testutil {
    #[derive(Debug)]
    pub(crate) struct MillisecondsSinceEpoch(pub u64);

    impl MillisecondsSinceEpoch {
        pub(crate) const TEST_VALUE: Self = FIXED_DATE;
    }

    pub(crate) const FIXED_DATE: MillisecondsSinceEpoch = {
        const YEARS: u64 = 2024 - 1970;
        const SECONDS: u64 = YEARS * 365 * 24 * 60 * 60;
        // Late 2023 (because of leap years)
        MillisecondsSinceEpoch(SECONDS * 1000)
    };
}

#[cfg(test)]
mod test {
    use test_case::{test_case, test_matrix};

    use super::*;
    use crate::backup::time::testutil::{MillisecondsSinceEpoch, FIXED_DATE};

    impl Timestamp {
        pub(crate) fn test_value() -> Self {
            Self(
                UNIX_EPOCH + std::time::Duration::from_millis(MillisecondsSinceEpoch::TEST_VALUE.0),
            )
        }
    }

    fn non_hermetic_current_time() -> MillisecondsSinceEpoch {
        MillisecondsSinceEpoch(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .try_into()
                .unwrap(),
        )
    }

    fn mistakenly_seconds(time: MillisecondsSinceEpoch) -> u64 {
        time.0 / 1000
    }
    fn mistakenly_microseconds(time: MillisecondsSinceEpoch) -> u64 {
        time.0 * 1000
    }

    #[test_case(FIXED_DATE)]
    #[test_case(non_hermetic_current_time())]
    fn timestamp_accepted(milliseconds: MillisecondsSinceEpoch) {
        testing_logger::setup();
        let _ = Timestamp::from_millis(milliseconds.0, "test_field");
        testing_logger::validate(|captured_logs| assert_eq!(captured_logs.len(), 0));
    }

    #[test_matrix((FIXED_DATE, non_hermetic_current_time()), (mistakenly_seconds, mistakenly_microseconds))]
    fn timestamp_rejected(
        timestamp: MillisecondsSinceEpoch,
        apply: fn(MillisecondsSinceEpoch) -> u64,
    ) {
        testing_logger::setup();
        let allegedly_milliseconds = apply(timestamp);

        let _ = Timestamp::from_millis(allegedly_milliseconds, "allegedly milliseconds");
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert!(captured_logs
                .first()
                .unwrap()
                .body
                .contains("allegedly milliseconds"))
        });
    }
}
