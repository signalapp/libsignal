//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::fmt::Debug;
use std::time::{Duration, SystemTime};

use crate::backup::account_data::{AccountData, AccountDataError};
use crate::backup::frame::{
    CallId, ChatId, GetForeignId as _, RecipientId, RingerRecipientId, WithId,
};
use crate::backup::method::{KeyExists, Map as _, Method, Store, ValidateOnly};
use crate::proto::backup as proto;
use crate::proto::backup::frame::Item as FrameItem;

mod account_data;
mod frame;
pub(crate) mod method;

pub struct PartialBackup<M: Method> {
    version: u64,
    backup_time: M::Value<SystemTime>,
    account_data: Option<M::Value<AccountData<M>>>,
    recipients: M::Map<RecipientId, proto::Recipient>,
    chats: M::Map<ChatId, proto::Chat>,
    calls: M::Map<CallId, proto::Call>,
}

#[derive(Debug)]
pub struct Backup {
    pub version: u64,
    pub backup_time: SystemTime,
    pub account_data: Option<AccountData<Store>>,
    pub recipients: HashMap<RecipientId, proto::Recipient>,
    pub chats: HashMap<ChatId, proto::Chat>,
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
    /// multiple records found for {0:?}
    DuplicateRecipient(RecipientId),
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
pub enum ChatError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoRecipient(RecipientId),
    /// no record for chat
    NoChatForItem,
    /// no record for chat item author
    NoAuthor(RecipientId),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum CallError {
    /// multiple records with the same ID
    DuplicateId,
    /// no record for {0:?}
    NoConversation(ChatId),
    /// no record for {0:?}
    NoRingerRecipient(RingerRecipientId),
}

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
            FrameItem::Recipient(recipient) => self.add_recipient(recipient),
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

    fn add_recipient(&mut self, recipient: proto::Recipient) -> Result<(), ValidationError> {
        let id = recipient.id();
        self.recipients
            .insert(id, recipient)
            .map_err(|KeyExists| ValidationError::DuplicateRecipient(id))
    }

    fn add_chat(&mut self, chat: proto::Chat) -> Result<(), ChatFrameError> {
        let id = chat.id();
        let recipient_id = chat.foreign_id();

        if !self.recipients.contains(&recipient_id) {
            return Err(ChatFrameError(id, ChatError::NoRecipient(recipient_id)));
        }

        self.chats
            .insert(id, chat)
            .map_err(|KeyExists| ChatFrameError(id, ChatError::DuplicateId))
    }

    fn add_chat_item(&mut self, chat_item: proto::ChatItem) -> Result<(), ChatFrameError> {
        let chat_id = chat_item.foreign_id();
        let author_id = chat_item.foreign_id();

        if !self.chats.contains(&chat_id) {
            return Err(ChatFrameError(chat_id, ChatError::NoChatForItem));
        }
        if !self.recipients.contains(&author_id) {
            return Err(ChatFrameError(chat_id, ChatError::NoAuthor(author_id)));
        }

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

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::{test_case, test_matrix};

    use super::*;

    impl proto::Recipient {
        const TEST_ID: u64 = 11111;
        fn test_data() -> Self {
            Self {
                id: Self::TEST_ID,
                ..Default::default()
            }
        }
    }

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
        const TEST_ID: u64 = 33333;
        fn test_data() -> Self {
            Self {
                callId: Self::TEST_ID,
                conversationRecipientId: proto::Chat::TEST_ID,
                ringerRecipientId: proto::Recipient::TEST_ID,
                ..Default::default()
            }
        }
        fn test_data_wrong_ringer() -> Self {
            Self {
                callId: Self::TEST_ID,
                conversationRecipientId: proto::Chat::TEST_ID,
                ringerRecipientId: proto::Recipient::TEST_ID + 1,
                ..Default::default()
            }
        }
    }

    impl proto::ChatItem {
        fn test_data() -> Self {
            Self {
                chatId: proto::Chat::TEST_ID,
                authorId: proto::Recipient::TEST_ID,
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
}
