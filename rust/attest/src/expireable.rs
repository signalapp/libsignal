//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

pub(crate) trait Expireable {
    fn valid_at(&self, timestamp: SystemTime) -> bool;
}
