//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::common::sho::Sho;
use crate::common::simple_types::Timestamp;

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampStruct {
    pub(crate) timestamp: Timestamp,
}

impl TimestampStruct {
    pub fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }

    pub fn calc_m(&self) -> Scalar {
        Self::calc_m_from(self.timestamp)
    }

    pub fn calc_m_from(timestamp: Timestamp) -> Scalar {
        let mut sho = Sho::new(
            b"Signal_ZKGroup_20220524_Timestamp_Calc_m",
            &timestamp.to_be_bytes(),
        );
        sho.get_scalar()
    }
}
