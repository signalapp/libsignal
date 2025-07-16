//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// The code in question looks like
//    self.special_fields.cached_size().set(my_size as u32)
// which isn't obviously correct! But protobuf doesn't support messages that big anyway.
#![expect(clippy::cast_possible_truncation)]

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

pub use protobuf::Message;
