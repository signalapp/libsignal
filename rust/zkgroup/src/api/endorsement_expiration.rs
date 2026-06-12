//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{SECONDS_PER_DAY, Timestamp, ZkGroupVerificationFailure};

const SECONDS_PER_HOUR: u64 = 60 * 60;

pub(crate) fn default_expiration(current_time: Timestamp) -> Timestamp {
    // Return the end of the next day, unless that's less than 25 hours away.
    // In that case, return the end of the following day.
    let current_time_in_seconds = current_time.epoch_seconds();
    let start_of_day = current_time_in_seconds - (current_time_in_seconds % SECONDS_PER_DAY);
    let mut expiration = start_of_day + 2 * SECONDS_PER_DAY;
    if (expiration - current_time_in_seconds) < SECONDS_PER_DAY + SECONDS_PER_HOUR {
        expiration += SECONDS_PER_DAY;
    }
    Timestamp::from_epoch_seconds(expiration)
}

pub(crate) fn validate_expiration(
    expiration: Timestamp,
    now: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    if !expiration.is_day_aligned() {
        // Reject credentials that don't expire on a day boundary,
        // because the server might be trying to fingerprint us.
        return Err(ZkGroupVerificationFailure);
    }
    let time_remaining_in_seconds = expiration.saturating_seconds_since(now);
    if time_remaining_in_seconds < 2 * SECONDS_PER_HOUR {
        // Reject credentials that expire in less than two hours,
        // including those that might expire in the past.
        // Two hours allows for clock skew plus incorrect summer time settings (+/- 1 hour).
        return Err(ZkGroupVerificationFailure);
    }
    if time_remaining_in_seconds > 7 * SECONDS_PER_DAY {
        // Reject credentials with expirations more than 7 days from now,
        // because the server might be trying to fingerprint us.
        return Err(ZkGroupVerificationFailure);
    }
    Ok(())
}
