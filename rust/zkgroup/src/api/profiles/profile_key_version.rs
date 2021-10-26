//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};

#[derive(Copy, Clone)]
pub struct ProfileKeyVersion {
    pub(crate) bytes: ProfileKeyVersionEncodedBytes,
}

impl Serialize for ProfileKeyVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.bytes.len()).unwrap();
        for b in self.bytes.iter() {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}
