//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::ops::Add;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(SystemTime);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum TimestampOrForever {
    Timestamp(Timestamp),
    Forever,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(std::time::Duration);

/// Describes an unusual timestamp.
///
/// See [`Timestamp::from_millis`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, displaydoc::Display)]
pub enum TimestampIssue {
    /// unexpectedly zero
    Zero,
    /// far in the past
    Past,
    /// far in the future
    Future,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
/// Timestamp {1} for '{0}' was too far in the future
pub struct TimestampError(pub(crate) &'static str, pub(crate) u64);

/// Callback for when a backup frame contains an unusual timestamp.
///
/// See [`Timestamp::from_millis`].
pub trait ReportUnusualTimestamp {
    #[track_caller]
    fn report(&self, since_epoch: u64, context: &'static str, issue: TimestampIssue);
}

/// A [`ReportUnusualTimestamp`] implementor that suppresses warnings about particular issues if
/// they recur too many times.
#[derive(Default)]
pub struct UnusualTimestampTracker(
    // We track *both* caller location *and* context string in case either is insufficient to
    // uniquely identify the source of an issue (a reused helper could result in the same location;
    // an overly general description could result in the same context string). In practice, they
    // will probably line up. We also track the issue detected, since different issues may have
    // different causes.
    HashMap<(std::panic::Location<'static>, &'static str, TimestampIssue), u8>,
);

impl Timestamp {
    /// A reasonable range for timestamps found in backup files; timestamps outside of this range
    /// will be warned about.
    const EXPECTED_RANGE_MS: std::ops::Range<u64> =
        // 2000-01-01 - UNIX_EPOCH
        946_684_800_000..
        // 2100-01-01 - UNIX_EPOCH
        4_102_444_800_000;

    /// The maximum timestamp we allow in backup files, also the limit of JavaScript's Date type.
    const MAX_SAFE_TIMESTAMP_MS: u64 = 100_000_000 * 1000 * 60 * 60 * 24;

    /// Validates and converts a timestamp represented as seconds since [`UNIX_EPOCH`].
    ///
    /// If the timestamp is unlikely to represent an event during Signal's history, `reporter` is
    /// notified with the given `context` (usually a description of the protobuf message and field
    /// containing the timestamp). However, since many timestamps are set by other clients, or
    /// depend on the local system's clock being set correctly, "unusual" timestamps do not produce
    /// hard errors.
    #[track_caller]
    pub fn from_millis(
        since_epoch: u64,
        context: &'static str,
        reporter: &dyn ReportUnusualTimestamp,
    ) -> Result<Self, TimestampError> {
        if since_epoch < Self::EXPECTED_RANGE_MS.start {
            let issue = if since_epoch == 0 {
                TimestampIssue::Zero
            } else {
                TimestampIssue::Past
            };
            reporter.report(since_epoch, context, issue);
        } else if since_epoch > Self::EXPECTED_RANGE_MS.end {
            if since_epoch > Self::MAX_SAFE_TIMESTAMP_MS {
                return Err(TimestampError(context, since_epoch));
            }
            reporter.report(since_epoch, context, TimestampIssue::Future);
        }
        Ok(Self(
            UNIX_EPOCH + std::time::Duration::from_millis(since_epoch),
        ))
    }

    pub(super) fn into_inner(self) -> SystemTime {
        self.0
    }

    pub fn as_millis(&self) -> u64 {
        self.0
            .duration_since(UNIX_EPOCH)
            .expect("should not be possible to construct a Timestamp older than UNIX_EPOCH")
            .as_millis()
            .try_into()
            .expect("should not be possible to construct a Timestamp that requires u128 millis since UNIX_EPOCH")
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_millis().serialize(serializer)
    }
}

impl TimestampOrForever {
    const FOREVER_MS: u64 = i64::MAX as u64; // As used for Chat.muteUntilMs.

    #[track_caller]
    pub fn from_millis(
        since_epoch: u64,
        context: &'static str,
        reporter: &dyn ReportUnusualTimestamp,
    ) -> Result<Self, TimestampError> {
        Ok(if since_epoch >= Self::FOREVER_MS {
            Self::Forever
        } else {
            Self::Timestamp(Timestamp::from_millis(since_epoch, context, reporter)?)
        })
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

impl<T: ReportUnusualTimestamp + ?Sized> ReportUnusualTimestamp for &'_ T {
    fn report(&self, since_epoch: u64, context: &'static str, issue: TimestampIssue) {
        (*self).report(since_epoch, context, issue)
    }
}

impl UnusualTimestampTracker {
    // Note: distinct from ReportUnusualTimestamp, this requires `&mut self`.
    pub fn report(&mut self, since_epoch: u64, context: &'static str, issue: TimestampIssue) {
        const SUPPRESS_AFTER_N_LOGS: u8 = 4;
        let entry = self
            .0
            .entry((*std::panic::Location::caller(), context, issue))
            .or_default();
        let suppression_note = match (*entry).cmp(&SUPPRESS_AFTER_N_LOGS) {
            std::cmp::Ordering::Less => "",
            std::cmp::Ordering::Equal => " (further warnings will be suppressed)",
            std::cmp::Ordering::Greater => return,
        };
        *entry += 1;

        log::warn!("timestamp {context} value {since_epoch} is {issue}{suppression_note}");
    }
}

impl ReportUnusualTimestamp for std::cell::RefCell<UnusualTimestampTracker> {
    #[track_caller]
    fn report(&self, since_epoch: u64, context: &'static str, issue: TimestampIssue) {
        self.borrow_mut().report(since_epoch, context, issue)
    }
}

#[cfg(test)]
pub(super) mod testutil {
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct MillisecondsSinceEpoch(pub u64);

    impl MillisecondsSinceEpoch {
        pub(crate) const TEST_VALUE: Self = FIXED_DATE;

        /// Just out of the allowed range for backup timestamps.
        pub(crate) const FAR_FUTURE: Self = {
            const DAYS: u64 = 100_000_000;
            const SECONDS: u64 = DAYS * 24 * 60 * 60;
            MillisecondsSinceEpoch(SECONDS * 1000 + 1)
        };
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
    use std::cell::RefCell;

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
        let tracker: RefCell<UnusualTimestampTracker> = Default::default();
        let _ = Timestamp::from_millis(milliseconds.0, "test_field", &tracker);
        assert_eq!(&tracker.into_inner().0, &HashMap::default());
    }

    #[test_matrix((FIXED_DATE, non_hermetic_current_time()), (mistakenly_seconds, mistakenly_microseconds))]
    fn timestamp_rejected(
        timestamp: MillisecondsSinceEpoch,
        apply: fn(MillisecondsSinceEpoch) -> u64,
    ) {
        let allegedly_milliseconds = apply(timestamp);
        let description = "allegedly milliseconds";

        let tracker: RefCell<UnusualTimestampTracker> = Default::default();
        let _ = Timestamp::from_millis(allegedly_milliseconds, description, &tracker);

        let &[((_location, context, problem), count)] = &Vec::from_iter(tracker.into_inner().0)[..]
        else {
            panic!("failed to reject {allegedly_milliseconds}");
        };

        assert_eq!(count, 1, "failed to count properly");
        assert_eq!(context, description);
        assert_eq!(
            problem,
            if allegedly_milliseconds < timestamp.0 {
                TimestampIssue::Past
            } else {
                TimestampIssue::Future
            }
        );
    }

    #[test_matrix([MillisecondsSinceEpoch::FAR_FUTURE.0, i64::MAX as u64, u64::MAX])]
    fn timestamp_hard_error(raw_timestamp: u64) {
        let tracker: RefCell<UnusualTimestampTracker> = Default::default();
        assert_eq!(
            Timestamp::from_millis(raw_timestamp, "test", &tracker),
            Err(TimestampError("test", raw_timestamp))
        );
        assert_eq!(
            0,
            tracker.into_inner().0.len(),
            "nothing should be added to the tracker"
        );
    }
}
