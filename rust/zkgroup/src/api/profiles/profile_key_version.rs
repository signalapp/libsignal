//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

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
