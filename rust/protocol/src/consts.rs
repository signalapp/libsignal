//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

pub const MAX_FORWARD_JUMPS: usize = 25_000;
pub const MAX_MESSAGE_KEYS: usize = 2000;
pub const MAX_RECEIVER_CHAINS: usize = 5;
pub const ARCHIVED_STATES_MAX_LENGTH: usize = 40;
pub const MAX_SENDER_KEY_STATES: usize = 5;

/// Sessions that have not gotten a response after this interval will be considered "soft archived"
/// and will not be available for sending.
///
/// Set to 30 days to match the length clients kept pre-keys in their stores (at the time this
/// expiration was added), but the two durations aren't actually tied together: if Alice fetches
/// pre-keys on day 29, and Bob deletes them on day 30, Alice will still try to use them on day 32
/// even with a shorter max session age.
///
/// Lower values result in senders resetting their sessions more often (by fetching new pre-keys
/// from the server). Higher values result in a higher likelihood that the sender will send a
/// message the receiver no longer has the keys to process.
pub const MAX_UNACKNOWLEDGED_SESSION_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 30);
