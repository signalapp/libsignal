//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::backup::{Call, Chat, ChatItem, Recipient};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecipientId(pub(super) u64);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChatId(u64);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct CallId(pub(super) u64);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RingerRecipientId(RecipientId);

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

pub(super) trait WithId {
    type Id;
    fn id(&self) -> Self::Id;
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

pub(super) trait WithForeignId<Id> {
    fn foreign_id(&self) -> Id;
}

/// Convenience trait for writing `foreign_id::<Xyz>()`.
pub(super) trait GetForeignId {
    fn foreign_id<Id>(&self) -> Id
    where
        Self: WithForeignId<Id>,
    {
        WithForeignId::foreign_id(self)
    }
}

impl<T> GetForeignId for T {}

macro_rules! impl_with_foreign_id {
    ($proto:ty, $id:ident, $id_field:ident) => {
        impl WithForeignId<$id> for $proto {
            fn foreign_id(&self) -> $id {
                $id(self.$id_field)
            }
        }
    };
}

impl_with_foreign_id!(Chat, RecipientId, recipientId);
impl_with_foreign_id!(ChatItem, ChatId, chatId);
impl_with_foreign_id!(ChatItem, RecipientId, authorId);
impl_with_foreign_id!(Call, ChatId, conversationRecipientId);
impl WithForeignId<Option<RingerRecipientId>> for Call {
    fn foreign_id(&self) -> Option<RingerRecipientId> {
        // TODO make the proto field optional.
        self.ringerRecipientId
            .map(RecipientId)
            .map(RingerRecipientId)
    }
}
