//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::{hash_map, HashMap};
use std::fmt::Debug;
use std::time::{Duration, SystemTime};

use crate::backup::account_data::{AccountData, AccountDataError};
use crate::backup::chat::{ChatData, ChatError, ChatItemError};
use crate::backup::frame::{
    CallId, ChatId, GetForeignId as _, RecipientId, RingerRecipientId, WithId,
};
use crate::backup::method::{Contains, KeyExists, Map as _, Method, Store, ValidateOnly};
use crate::backup::recipient::{RecipientData, RecipientError};
use crate::proto::backup as proto;
use crate::proto::backup::frame::Item as FrameItem;

mod account_data;
mod chat;
mod frame;
pub(crate) mod method;
mod recipient;

pub struct PartialBackup<M: Method> {
    version: u64,
    backup_time: M::Value<SystemTime>,
    account_data: Option<M::Value<AccountData<M>>>,
    recipients: M::Map<RecipientId, RecipientData<M>>,
    chats: HashMap<ChatId, ChatData<M>>,
    calls: M::Map<CallId, proto::Call>,
}

#[derive(Debug)]
pub struct Backup {
    pub version: u64,
    pub backup_time: SystemTime,
    pub account_data: Option<AccountData<Store>>,
    pub recipients: HashMap<RecipientId, RecipientData>,
    pub chats: HashMap<ChatId, ChatData>,
    pub calls: HashMap<CallId, proto::Call>,
}

impl From<PartialBackup<Store>> for Backup {
    fn from(value: PartialBackup<Store>) -> Self {
        let PartialBackup {
            version,
            backup_time,
            account_data,
            recipients,
            chats,
            calls,
        } = value;

        Self {
            version,
            backup_time,
            account_data,
            recipients,
            chats,
            calls,
        }
    }
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum ValidationError {
    /// no item in frame
    EmptyFrame,
    /// multiple AccountData frames found
    MultipleAccountData,
    /// AccountData error: {0}
    AccountData(#[from] AccountDataError),
    /// {0}
    RecipientError(#[from] RecipientFrameError),
    /// {0}
    ChatError(#[from] ChatFrameError),
    /// {0}
    CallError(#[from] CallFrameError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
/// chat frame {0:?} error: {1}
pub struct ChatFrameError(ChatId, ChatError);

/// call data {0:?} error: {1}
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub struct CallFrameError(CallId, CallError);

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum CallError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoConversation(ChatId),
    /// no record for {0:?}
    NoRingerRecipient(RingerRecipientId),
}

/// Like [`TryFrom`] but with an extra context argument.
///
/// Implements fallible conversions from `T` into `Self` with an additional
/// "context" argument.
trait TryFromWith<T, C>: Sized {
    type Error;

    /// Uses additional context to convert `item` into an instance of `Self`.
    ///
    /// If the lookup fails, an instance of `Self::Error` is returned.
    fn try_from_with(item: T, context: &C) -> Result<Self, Self::Error>;
}

/// Like [`TryInto`] but with an extra context argument.
///
/// This trait is blanket-implemented for types that implement [`TryFromWith`].
/// Its only purpose is to offer the more convenient `x.try_into_with(c)` as
/// opposed to `Y::try_from_with(x, c)`.
trait TryIntoWith<T, C>: Sized {
    type Error;

    /// Uses additional context to convert `self` into an instance of `T`.
    ///
    /// If the lookup fails, an instance of `Self::Error` is returned.
    fn try_into_with(self, context: &C) -> Result<T, Self::Error>;
}

impl<A, B: TryFromWith<A, C>, C> TryIntoWith<B, C> for A {
    type Error = B::Error;
    fn try_into_with(self, context: &C) -> Result<B, Self::Error> {
        B::try_from_with(self, context)
    }
}

/// recipient {0:?} error: {1}
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub struct RecipientFrameError(RecipientId, RecipientError);

impl PartialBackup<ValidateOnly> {
    pub fn new_validator(value: proto::BackupInfo) -> Self {
        Self::new(value)
    }
}

impl PartialBackup<Store> {
    pub fn new_store(value: proto::BackupInfo) -> Self {
        Self::new(value)
    }
}

impl<M: Method> PartialBackup<M> {
    pub fn new(value: proto::BackupInfo) -> Self {
        let proto::BackupInfo {
            version,
            backupTimeMs,
            special_fields: _,
        } = value;

        Self {
            version,
            backup_time: M::value(SystemTime::UNIX_EPOCH + Duration::from_millis(backupTimeMs)),
            account_data: None,
            recipients: Default::default(),
            chats: Default::default(),
            calls: Default::default(),
        }
    }

    pub fn add_frame(&mut self, frame: proto::Frame) -> Result<(), ValidationError> {
        self.add_frame_item(frame.item.ok_or(ValidationError::EmptyFrame)?)
    }

    fn add_frame_item(&mut self, item: FrameItem) -> Result<(), ValidationError> {
        match item {
            FrameItem::Account(account_data) => self.add_account_data(account_data),
            FrameItem::Recipient(recipient) => self.add_recipient(recipient).map_err(Into::into),
            FrameItem::Chat(chat) => self.add_chat(chat).map_err(Into::into),
            FrameItem::ChatItem(chat_item) => self.add_chat_item(chat_item).map_err(Into::into),
            FrameItem::Call(call) => self.add_call(call).map_err(Into::into),
            FrameItem::StickerPack(sticker_pack) => self.add_sticker_pack(sticker_pack),
        }
    }

    fn add_account_data(
        &mut self,
        account_data: proto::AccountData,
    ) -> Result<(), ValidationError> {
        if self.account_data.is_some() {
            return Err(ValidationError::MultipleAccountData);
        }
        let account_data = account_data.try_into()?;
        self.account_data = Some(M::value(account_data));
        Ok(())
    }

    fn add_recipient(&mut self, recipient: proto::Recipient) -> Result<(), RecipientFrameError> {
        let id = recipient.id();
        let err_with_id = |e| RecipientFrameError(id, e);
        let recipient = recipient.try_into().map_err(err_with_id)?;
        self.recipients
            .insert(id, recipient)
            .map_err(|KeyExists| err_with_id(RecipientError::DuplicateRecipient))
    }

    fn add_chat(&mut self, chat: proto::Chat) -> Result<(), ChatFrameError> {
        let id = chat.id();
        let recipient_id = chat.foreign_id();

        if !self.recipients.contains(&recipient_id) {
            return Err(ChatFrameError(id, ChatError::NoRecipient(recipient_id)));
        }

        let chat = chat.try_into().map_err(|e| ChatFrameError(id, e))?;
        match self.chats.entry(id) {
            hash_map::Entry::Occupied(_) => Err(ChatFrameError(id, ChatError::DuplicateId)),
            hash_map::Entry::Vacant(v) => {
                let _ = v.insert(chat);
                Ok(())
            }
        }
    }

    fn add_chat_item(&mut self, chat_item: proto::ChatItem) -> Result<(), ChatFrameError> {
        let chat_id = chat_item.foreign_id();
        let author_id = chat_item.foreign_id();

        let chat_data = match self.chats.entry(chat_id) {
            hash_map::Entry::Occupied(o) => o.into_mut(),
            hash_map::Entry::Vacant(_) => {
                return Err(ChatFrameError(chat_id, ChatItemError::NoChatForItem.into()))
            }
        };

        if !self.recipients.contains(&author_id) {
            return Err(ChatFrameError(
                chat_id,
                ChatItemError::AuthorNotFound(author_id).into(),
            ));
        }

        chat_data.items.extend([chat_item
            .try_into_with(&ChatContext {
                recipients: &self.recipients,
                calls: &self.calls,
            })
            .map_err(|e: ChatItemError| ChatFrameError(chat_id, e.into()))?]);

        Ok(())
    }

    fn add_call(&mut self, call: proto::Call) -> Result<(), CallFrameError> {
        let call_id = call.id();
        let conversation_recipient_id = call.foreign_id::<ChatId>();
        let ringer_recipient_id = call.foreign_id::<Option<RingerRecipientId>>();

        if !self.chats.contains(&conversation_recipient_id) {
            return Err(CallFrameError(
                call_id,
                CallError::NoConversation(conversation_recipient_id),
            ));
        }

        if let Some(ringer_recipient_id) = ringer_recipient_id {
            if !self.recipients.contains(&ringer_recipient_id.into()) {
                return Err(CallFrameError(
                    call_id,
                    CallError::NoRingerRecipient(ringer_recipient_id),
                ));
            }
        }

        self.calls
            .insert(call_id, call)
            .map_err(|KeyExists| CallFrameError(call_id, CallError::DuplicateId))?;

        Ok(())
    }

    fn add_sticker_pack(
        &mut self,
        _sticker_pack: proto::StickerPack,
    ) -> Result<(), ValidationError> {
        // TODO validate sticker pack proto.
        Ok(())
    }
}

/// Implementer of [`Contains`] for [`RecipientId`] and [`CallId`].
///
/// This is used as the concrete "context" type for the [`TryFromWith`]
/// implementations below.
pub(super) struct ChatContext<'a, Recipients, Calls> {
    pub(super) recipients: &'a Recipients,
    pub(super) calls: &'a Calls,
}

impl<R: Contains<RecipientId>, C> Contains<RecipientId> for ChatContext<'_, R, C> {
    fn contains(&self, key: &RecipientId) -> bool {
        self.recipients.contains(key)
    }
}

impl<R, C: Contains<CallId>> Contains<CallId> for ChatContext<'_, R, C> {
    fn contains(&self, key: &CallId) -> bool {
        self.calls.contains(key)
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::{test_case, test_matrix};

    use super::*;

    impl proto::Chat {
        const TEST_ID: u64 = 22222;
        fn test_data() -> Self {
            Self {
                id: Self::TEST_ID,
                recipientId: proto::Recipient::TEST_ID,
                ..Default::default()
            }
        }
    }

    impl proto::Call {
        pub(super) const TEST_ID: u64 = 33333;
        pub(super) fn test_data() -> Self {
            Self {
                callId: Self::TEST_ID,
                conversationRecipientId: proto::Chat::TEST_ID,
                ringerRecipientId: Some(proto::Recipient::TEST_ID),
                ..Default::default()
            }
        }
        fn test_data_no_ringer() -> Self {
            Self {
                ringerRecipientId: None,
                ..Self::test_data()
            }
        }
        fn test_data_wrong_ringer() -> Self {
            Self {
                ringerRecipientId: Some(proto::Recipient::TEST_ID + 1),
                ..Self::test_data()
            }
        }
    }

    impl proto::ChatItem {
        fn test_data() -> Self {
            Self {
                chatId: proto::Chat::TEST_ID,
                authorId: proto::Recipient::TEST_ID,
                item: Some(proto::chat_item::Item::StandardMessage(
                    proto::StandardMessage::test_data(),
                )),
                ..Default::default()
            }
        }

        fn test_data_wrong_author() -> Self {
            Self {
                chatId: proto::Chat::TEST_ID,
                authorId: proto::Recipient::TEST_ID + 1,
                ..Default::default()
            }
        }
    }

    trait TestPartialBackupMethod: Method + Sized {
        fn empty() -> PartialBackup<Self> {
            PartialBackup::new(proto::BackupInfo::new())
        }

        fn fake() -> PartialBackup<Self> {
            Self::fake_with([
                proto::Recipient::test_data().into(),
                proto::Chat::test_data().into(),
                proto::Call::test_data().into(),
                proto::ChatItem::test_data().into(),
            ])
        }

        fn fake_with(frames: impl IntoIterator<Item = proto::frame::Item>) -> PartialBackup<Self> {
            let mut backup = Self::empty();

            for frame in frames {
                backup.add_frame_item(frame).expect("can add one");
            }
            backup
        }
    }

    impl<M: Method + Sized> TestPartialBackupMethod for M {}

    #[test_matrix(
        (ValidateOnly::fake(), Store::fake()),
        (proto::Recipient::test_data(), proto::Chat::test_data(), proto::Call::test_data())
    )]
    fn rejects_duplicate_id<M: Method>(mut partial: PartialBackup<M>, item: impl Into<FrameItem>) {
        let err = partial.add_frame_item(item.into()).unwrap_err().to_string();
        assert!(err.contains("multiple"), "error was {err}");
    }

    #[test_matrix(
        (ValidateOnly::empty(), Store::empty()),
        (proto::Chat::test_data(), proto::Call::test_data())
    )]
    #[test_case(
        ValidateOnly::fake_with([proto::Recipient::test_data().into()]),
        proto::ChatItem::test_data(); "missing chat item conversation"
    )]
    #[test_matrix(
        (ValidateOnly::fake(), Store::fake()),
        proto::ChatItem::test_data_wrong_author()
    )]
    #[test_case(
        ValidateOnly::fake_with([proto::Recipient::test_data().into(), proto::Chat::test_data().into()]),
        proto::Call::test_data_wrong_ringer()
    )]
    fn rejects_missing_foreign_key<M: Method>(
        mut partial: PartialBackup<M>,
        item: impl Into<FrameItem>,
    ) {
        let frame = proto::Frame {
            item: Some(item.into()),
            ..Default::default()
        };

        let err = partial.add_frame(frame).unwrap_err().to_string();
        assert!(err.contains("no record"), "error was {err}");
    }

    #[test_case(ValidateOnly::empty())]
    #[test_case(Store::empty())]
    fn rejects_multiple_account_data(mut partial: PartialBackup<impl Method>) {
        partial
            .add_frame_item(proto::AccountData::test_data().into())
            .expect("accepts first");

        assert_matches!(
            partial.add_frame_item(proto::AccountData::test_data().into()),
            Err(ValidationError::MultipleAccountData)
        );
    }

    #[test]
    fn allows_call_without_ringer_id() {
        let mut partial = ValidateOnly::fake_with([
            proto::Recipient::test_data().into(),
            proto::Chat::test_data().into(),
        ]);
        assert_matches!(
            partial.add_frame_item(proto::Call::test_data_no_ringer().into()),
            Ok(())
        );
    }
}
