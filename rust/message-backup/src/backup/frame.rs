//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::backup::WithId;
use crate::proto::backup::{Call, Chat, Recipient};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecipientId(pub(super) u64);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChatId(pub(super) u64);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct CallId(pub(super) u64);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RingerRecipientId(pub(super) RecipientId);

impl From<RingerRecipientId> for RecipientId {
    fn from(value: RingerRecipientId) -> Self {
        value.0
    }
}

impl PartialEq<RecipientId> for RingerRecipientId {
    fn eq(&self, other: &RecipientId) -> bool {
        &self.0 == other
    }
}

macro_rules! impl_with_id {
    ($proto:ty, $id:ident, $id_field:ident) => {
        impl WithId for $proto {
            type Id = $id;

            fn id(&self) -> Self::Id {
                $id(self.$id_field)
            }
        }
    };
}

impl_with_id!(Chat, ChatId, id);
impl_with_id!(Recipient, RecipientId, id);
impl_with_id!(Call, CallId, callId);
