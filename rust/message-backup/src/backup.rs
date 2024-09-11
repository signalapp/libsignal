//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::{hash_map, HashMap};
use std::fmt::Debug;
use std::sync::Arc;

use derive_where::derive_where;
use libsignal_core::Aci;

pub(crate) use crate::backup::account_data::{AccountData, AccountDataError};
use crate::backup::call::{AdHocCall, CallError};
use crate::backup::chat::chat_style::{CustomChatColor, CustomColorId};
use crate::backup::chat::{ChatData, ChatError, ChatItemData, ChatItemError, PinOrder};
use crate::backup::frame::{ChatId, RecipientId};
use crate::backup::method::{Lookup, LookupPair, Method, Store, ValidateOnly};
use crate::backup::recipient::{
    DestinationKind, FullRecipientData, MinimalRecipientData, RecipientError,
};
use crate::backup::serialize::SerializeOrder;
use crate::backup::sticker::{PackId as StickerPackId, StickerPack, StickerPackError};
use crate::backup::time::Timestamp;
use crate::proto::backup as proto;
use crate::proto::backup::frame::Item as FrameItem;

mod account_data;
mod call;
mod chat;
mod file;
mod frame;
pub(crate) mod method;
mod recipient;
pub mod serialize;
mod sticker;
mod time;

#[cfg(test)]
mod testutil;

pub trait ReferencedTypes {
    /// Recorded information from a [`proto::Recipient`].
    type RecipientData: Debug + AsRef<DestinationKind>;
    /// Resolved data for a [`RecipientId`] in a non-`proto::Recipient` message.
    type RecipientReference: Clone + Debug + serde::Serialize + SerializeOrder;

    /// Recorded information from a [`proto::chat_style::CustomChatColor`].
    type CustomColorData: Debug + From<CustomChatColor> + serde::Serialize;
    /// Resolved data for a [`CustomColorId`] in a non-`CustomChatColor` message.
    type CustomColorReference: Clone + Debug + serde::Serialize;

    fn color_reference<'a>(
        id: &'a CustomColorId,
        data: &'a Self::CustomColorData,
    ) -> &'a Self::CustomColorReference;

    /// Produces a reference to a recipient from its ID and data.
    fn recipient_reference<'a>(
        id: &'a RecipientId,
        data: &'a Self::RecipientData,
    ) -> &'a Self::RecipientReference;

    /// Parse a [`proto::Recipient`] into the in-memory form.
    ///
    /// This can't just be a [`TryFromWith`] bound on `Self::RecipientData`
    /// since we want it to be convertible from any context type with some
    /// bounds, and Rust doesn't have a way to express that. The closest thing
    /// would be to define an additional trait that bounds `Self::RecipientData`
    /// with one method that takes a context type with the `LookupPair` bound,
    /// but that doesn't seem to provide additional value.
    fn try_convert_recipient<
        C: LookupPair<RecipientId, DestinationKind, Self::RecipientReference>,
    >(
        recipient: proto::Recipient,
        context: &C,
    ) -> Result<Self::RecipientData, RecipientError>;
}

pub struct PartialBackup<M: Method + ReferencedTypes> {
    meta: BackupMeta,
    account_data: Option<AccountData<M>>,
    recipients: HashMap<RecipientId, M::RecipientData>,
    chats: ChatsData<M>,
    ad_hoc_calls: M::List<AdHocCall<M::RecipientReference>>,
    sticker_packs: HashMap<StickerPackId, StickerPack<M>>,
}

#[derive_where(Debug)]
pub struct CompletedBackup<M: Method + ReferencedTypes> {
    meta: BackupMeta,
    account_data: AccountData<M>,
    recipients: HashMap<RecipientId, M::RecipientData>,
    chats: ChatsData<M>,
    ad_hoc_calls: M::List<AdHocCall<M::RecipientReference>>,
    sticker_packs: HashMap<StickerPackId, StickerPack<M>>,
}

pub type Backup = CompletedBackup<Store>;

#[derive_where(Debug, Default)]
struct ChatsData<M: Method + ReferencedTypes> {
    items: HashMap<ChatId, ChatData<M>>,
    pinned: Vec<(PinOrder, M::RecipientReference)>,
    /// Count of the total number of chat items held across all values in `items`.
    pub chat_items_count: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct BackupMeta {
    /// The version of the backup format being parsed.
    pub version: u64,
    /// When the backup process started.
    ///
    /// Omitted from the canonical backup string, so that subsequent backups can be compared.
    #[serde(skip)]
    pub backup_time: Timestamp,
    /// What purpose the backup was intended for.
    pub purpose: Purpose,
}

#[repr(u8)]
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    num_enum::TryFromPrimitive,
    strum::EnumString,
    strum::Display,
    strum::IntoStaticStr,
    serde::Serialize,
)]
pub enum Purpose {
    /// Intended for immediate transfer from one device to another.
    #[strum(
        serialize = "device_transfer",
        serialize = "device-transfer",
        serialize = "transfer"
    )]
    DeviceTransfer = 0,
    /// For remote storage and restoration at a later time.
    #[strum(
        serialize = "remote_backup",
        serialize = "remote-backup",
        serialize = "backup"
    )]
    RemoteBackup = 1,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum CompletionError {
    /// no AccountData frames found
    MissingAccountData,
}

impl<M: Method + ReferencedTypes> TryFrom<PartialBackup<M>> for CompletedBackup<M> {
    type Error = CompletionError;

    fn try_from(value: PartialBackup<M>) -> Result<Self, Self::Error> {
        let PartialBackup {
            meta,
            account_data,
            recipients,
            chats,
            ad_hoc_calls,
            sticker_packs,
        } = value;

        let account_data = account_data.ok_or(CompletionError::MissingAccountData)?;

        Ok(CompletedBackup {
            meta,
            account_data,
            recipients,
            chats,
            ad_hoc_calls,
            sticker_packs,
        })
    }
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum ValidationError {
    /// Frame.item is a oneof but has no value
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
    /// {0}
    StickerError(#[from] StickerError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
/// chat frame {0:?} error: {1}
pub struct ChatFrameError(ChatId, ChatError);

/// ad-hoc call (recipientId {recipient_id}, callId {call_id}) error: {error}
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub struct CallFrameError {
    recipient_id: u64,
    call_id: u64,
    error: CallError,
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

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum StickerError {
    /// pack ID is invalid
    InvalidId,
    /// multiple sticker packs for ID {0:?}
    DuplicateId(StickerPackId),
    /// for pack {0:?}: {1}
    PackError(StickerPackId, StickerPackError),
}

trait WithId {
    type Id;
    fn id(&self) -> Self::Id;
}

impl ReferencedTypes for Store {
    type RecipientReference = FullRecipientData;
    type RecipientData = FullRecipientData;

    type CustomColorData = Arc<CustomChatColor>;
    type CustomColorReference = Arc<CustomChatColor>;

    fn color_reference<'a>(
        _id: &'a CustomColorId,
        data: &'a Self::CustomColorData,
    ) -> &'a Self::CustomColorReference {
        data
    }

    fn recipient_reference<'a>(
        _id: &'a RecipientId,
        data: &'a Self::RecipientData,
    ) -> &'a Self::RecipientReference {
        data
    }

    fn try_convert_recipient<
        C: LookupPair<RecipientId, DestinationKind, Self::RecipientReference>,
    >(
        recipient: proto::Recipient,
        context: &C,
    ) -> Result<Self::RecipientData, RecipientError> {
        recipient.try_into_with(context)
    }
}

impl ReferencedTypes for ValidateOnly {
    type RecipientReference = RecipientId;
    type RecipientData = MinimalRecipientData;

    /// No need to keep any data for colors.
    type CustomColorData = ();
    type CustomColorReference = CustomColorId;

    fn color_reference<'a>(
        id: &'a CustomColorId,
        _data: &'a Self::CustomColorData,
    ) -> &'a Self::CustomColorReference {
        id
    }

    fn recipient_reference<'a>(
        id: &'a RecipientId,
        _data: &'a Self::RecipientData,
    ) -> &'a Self::RecipientReference {
        id
    }

    fn try_convert_recipient<
        C: LookupPair<RecipientId, DestinationKind, Self::RecipientReference>,
    >(
        recipient: proto::Recipient,
        context: &C,
    ) -> Result<Self::RecipientData, RecipientError> {
        MinimalRecipientData::try_from_with(recipient, context)
    }
}

/// recipient {0:?} error: {1}
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub struct RecipientFrameError(RecipientId, RecipientError);

impl PartialBackup<ValidateOnly> {
    pub fn new_validator(value: proto::BackupInfo, purpose: Purpose) -> Self {
        Self::new(value, purpose)
    }
}

impl PartialBackup<Store> {
    pub fn new_store(value: proto::BackupInfo, purpose: Purpose) -> Self {
        Self::new(value, purpose)
    }
}

impl<M: Method + ReferencedTypes> PartialBackup<M> {
    pub fn new(value: proto::BackupInfo, purpose: Purpose) -> Self {
        let proto::BackupInfo {
            version,
            backupTimeMs,
            special_fields: _,
        } = value;

        let meta = BackupMeta {
            version,
            backup_time: Timestamp::from_millis(backupTimeMs, "BackupInfo.backupTimeMs"),
            purpose,
        };

        Self {
            meta,
            account_data: None,
            recipients: Default::default(),
            chats: Default::default(),
            ad_hoc_calls: Default::default(),
            sticker_packs: HashMap::new(),
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
            FrameItem::StickerPack(sticker_pack) => {
                self.add_sticker_pack(sticker_pack).map_err(Into::into)
            }
            FrameItem::AdHocCall(call) => self.add_ad_hoc_call(call).map_err(Into::into),
        }
    }

    fn add_ad_hoc_call(&mut self, call: proto::AdHocCall) -> Result<(), CallFrameError> {
        let recipient_id = call.recipientId;
        let call_id = call.callId;
        let call = call.try_into_with(self).map_err(|error| CallFrameError {
            recipient_id,
            call_id,
            error,
        })?;
        self.ad_hoc_calls.extend(Some(call));
        Ok(())
    }

    fn add_account_data(
        &mut self,
        account_data: proto::AccountData,
    ) -> Result<(), ValidationError> {
        if self.account_data.is_some() {
            return Err(ValidationError::MultipleAccountData);
        }
        let account_data = account_data.try_into()?;
        self.account_data = Some(account_data);
        Ok(())
    }

    fn add_recipient(&mut self, recipient: proto::Recipient) -> Result<(), RecipientFrameError> {
        let id = recipient.id();
        let err_with_id = |e| RecipientFrameError(id, e);
        let recipient = M::try_convert_recipient(recipient, self).map_err(err_with_id)?;
        match self.recipients.entry(id) {
            hash_map::Entry::Occupied(_) => Err(err_with_id(RecipientError::DuplicateRecipient)),
            hash_map::Entry::Vacant(v) => {
                let _ = v.insert(recipient);
                Ok(())
            }
        }
    }

    fn add_chat(&mut self, chat: proto::Chat) -> Result<(), ChatFrameError> {
        let id = chat.id();

        let chat: ChatData<M> = chat
            .try_into_with(self)
            .map_err(|e| ChatFrameError(id, e))?;

        self.chats.add_chat(id, chat)?;
        Ok(())
    }

    fn add_chat_item(&mut self, chat_item: proto::ChatItem) -> Result<(), ValidationError> {
        let chat_id = ChatId(chat_item.chatId);

        let chat_item_data = chat_item
            .try_into_with(self)
            .map_err(|e: ChatItemError| ChatFrameError(chat_id, e.into()))?;

        Ok(self.chats.add_chat_item(chat_id, chat_item_data)?)
    }

    fn add_sticker_pack(&mut self, sticker_pack: proto::StickerPack) -> Result<(), StickerError> {
        let id = sticker_pack
            .packId
            .as_slice()
            .try_into()
            .map_err(|_| StickerError::InvalidId)?;
        let pack =
            StickerPack::try_from(sticker_pack).map_err(|e| StickerError::PackError(id, e))?;

        match self.sticker_packs.entry(id) {
            hash_map::Entry::Occupied(_) => Err(StickerError::DuplicateId(id)),
            hash_map::Entry::Vacant(v) => {
                v.insert(pack);
                Ok(())
            }
        }
    }
}

impl<M: Method + ReferencedTypes> ChatsData<M> {
    fn add_chat(&mut self, id: ChatId, chat: ChatData<M>) -> Result<(), ChatFrameError> {
        let Self {
            items,
            pinned,
            chat_items_count: _,
        } = self;

        match items.entry(id) {
            hash_map::Entry::Occupied(_) => Err(ChatFrameError(id, ChatError::DuplicateId)),
            hash_map::Entry::Vacant(v) => {
                if let Some(pin) = chat.pinned_order {
                    pinned.push((pin, chat.recipient.clone()));
                }
                let _ = v.insert(chat);
                Ok(())
            }
        }
    }

    fn add_chat_item(
        &mut self,
        chat_id: ChatId,
        mut item: ChatItemData<M>,
    ) -> Result<(), ChatFrameError> {
        let Self {
            chat_items_count,
            items,
            pinned: _,
        } = self;

        let chat_data = items
            .get_mut(&chat_id)
            .ok_or(ChatFrameError(chat_id, ChatItemError::NoChatForItem.into()))?;

        item.total_chat_item_order_index = *chat_items_count;

        chat_data.items.extend([item]);

        *chat_items_count += 1;

        Ok(())
    }
}

impl<M: Method + ReferencedTypes> Lookup<RecipientId, M::RecipientReference> for PartialBackup<M> {
    fn lookup<'a>(&'a self, key: &'a RecipientId) -> Option<&'a M::RecipientReference> {
        self.recipients
            .get(key)
            .map(|data| M::recipient_reference(key, data))
    }
}

impl<M: Method + ReferencedTypes> LookupPair<RecipientId, DestinationKind, M::RecipientReference>
    for PartialBackup<M>
{
    fn lookup_pair<'a>(
        &'a self,
        key: &'a RecipientId,
    ) -> Option<(&'a DestinationKind, &'a M::RecipientReference)> {
        self.recipients
            .get(key)
            .map(|data| (data.as_ref(), M::recipient_reference(key, data)))
    }
}

impl<M: Method + ReferencedTypes> Lookup<CustomColorId, M::CustomColorReference>
    for PartialBackup<M>
{
    fn lookup<'a>(&'a self, key: &'a CustomColorId) -> Option<&'a M::CustomColorReference> {
        self.account_data
            .as_ref()
            .and_then(|data| data.account_settings.custom_chat_colors.lookup(key))
    }
}

impl<M: Method + ReferencedTypes> Lookup<PinOrder, M::RecipientReference> for PartialBackup<M> {
    fn lookup(&self, key: &PinOrder) -> Option<&M::RecipientReference> {
        // This is a linear search, but the number of pinned chats should be
        // small enough in real backups that it's more efficient than a hash
        // lookup.
        self.chats
            .pinned
            .iter()
            .find_map(|(order, recipient)| (order == key).then_some(recipient))
    }
}

impl<M: Method + ReferencedTypes> AsRef<BackupMeta> for PartialBackup<M> {
    fn as_ref(&self) -> &BackupMeta {
        &self.meta
    }
}

#[cfg(feature = "json")]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConvertJsonError {
    /// input array was empty
    EmptyArray,
    /// failed to parse JSON as proto: {0}
    ProtoJsonParse(#[from] protobuf_json_mapping::ParseError),
    /// failed to print proto as JSON: {0}
    ProtoJsonPrint(#[from] protobuf_json_mapping::PrintError),
    /// JSON error: {0}
    Json(#[from] serde_json::Error),
    /// failed to encode/decode binary protobuf: {0}
    ProtoEncode(#[from] protobuf::Error),
    /// input/output error: {0}
    Io(#[from] std::io::Error),
}

#[cfg(feature = "json")]
impl From<crate::parse::ParseError> for ConvertJsonError {
    fn from(value: crate::parse::ParseError) -> Self {
        match value {
            crate::parse::ParseError::Decode(e) => e.into(),
            crate::parse::ParseError::Io(e) => e.into(),
        }
    }
}

#[cfg(feature = "json")]
pub fn convert_from_json(json: Vec<serde_json::Value>) -> Result<Box<[u8]>, ConvertJsonError> {
    let mut it = json.into_iter();

    let backup_info = protobuf_json_mapping::parse_from_str::<proto::BackupInfo>(
        &it.next().ok_or(ConvertJsonError::EmptyArray)?.to_string(),
    )?;

    let mut serialized = Vec::new();
    protobuf::Message::write_length_delimited_to_vec(&backup_info, &mut serialized)?;

    for json_frame in it {
        let frame = protobuf_json_mapping::parse_from_str::<proto::Frame>(&json_frame.to_string())?;

        protobuf::Message::write_length_delimited_to_vec(&frame, &mut serialized)?;
    }

    Ok(serialized.into_boxed_slice())
}

#[cfg(feature = "json")]
pub async fn convert_to_json(
    length_delimited_binproto: impl futures::AsyncRead + Unpin,
) -> Result<Vec<serde_json::Value>, ConvertJsonError> {
    fn binary_proto_to_json<M: protobuf::MessageFull>(
        binary: &[u8],
    ) -> Result<serde_json::Value, ConvertJsonError> {
        let proto = M::parse_from_bytes(binary)?;
        let json_proto = protobuf_json_mapping::print_to_string(&proto)?;
        Ok(serde_json::from_str(&json_proto)?)
    }

    let mut reader = crate::VarintDelimitedReader::new(length_delimited_binproto);

    let mut array = Vec::new();
    let backup_info = reader
        .read_next()
        .await?
        .ok_or(ConvertJsonError::EmptyArray)?;
    array.push(binary_proto_to_json::<proto::BackupInfo>(&backup_info)?);

    while let Some(frame) = reader.read_next().await? {
        array.push(binary_proto_to_json::<proto::Frame>(&frame)?);
    }
    Ok(array)
}

struct InvalidAci;

fn uuid_bytes_to_aci(bytes: Vec<u8>) -> Result<Aci, InvalidAci> {
    bytes
        .try_into()
        .map(Aci::from_uuid_bytes)
        .map_err(|_| InvalidAci)
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::{test_case, test_matrix};

    use super::*;

    impl proto::Chat {
        pub(super) const TEST_ID: u64 = 22222;
        pub(crate) fn test_data() -> Self {
            Self {
                id: Self::TEST_ID,
                recipientId: proto::Recipient::TEST_ID,
                ..Default::default()
            }
        }
    }

    impl proto::ChatItem {
        fn test_data_wrong_author() -> Self {
            Self {
                authorId: proto::Recipient::TEST_ID + 1,
                ..Self::test_data()
            }
        }
    }

    trait TestPartialBackupMethod: Method + ReferencedTypes + Sized {
        fn empty() -> PartialBackup<Self> {
            PartialBackup::new(proto::BackupInfo::new(), Purpose::RemoteBackup)
        }

        fn fake() -> PartialBackup<Self> {
            Self::fake_with([
                proto::Recipient::test_data().into(),
                proto::Chat::test_data().into(),
                proto::Recipient::test_data_contact().into(),
                // References both SELF_ID and CONTACT_ID
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

    impl<M: Method + ReferencedTypes> TestPartialBackupMethod for M {}

    #[test_matrix(
        (ValidateOnly::fake(), Store::fake()),
        (proto::Recipient::test_data(), proto::Chat::test_data())
    )]
    fn rejects_duplicate_id<M: Method + ReferencedTypes>(
        mut partial: PartialBackup<M>,
        item: impl Into<FrameItem>,
    ) {
        let err = partial.add_frame_item(item.into()).unwrap_err().to_string();
        assert!(err.contains("multiple"), "error was {err}");
    }

    #[test_matrix(
        (ValidateOnly::empty(), Store::empty()),
        proto::Chat::test_data()
    )]
    #[test_case(
        ValidateOnly::fake_with([proto::Recipient::test_data().into()]),
        proto::ChatItem::test_data(); "missing chat item conversation"
    )]
    #[test_matrix(
        (ValidateOnly::fake(), Store::fake()),
        proto::ChatItem::test_data_wrong_author()
    )]
    fn rejects_missing_foreign_key<M: Method + ReferencedTypes>(
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
    fn rejects_multiple_account_data<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_frame_item(proto::AccountData::test_data().into())
            .expect("accepts first");

        assert_matches!(
            partial.add_frame_item(proto::AccountData::test_data().into()),
            Err(ValidationError::MultipleAccountData)
        );
    }

    #[test]
    fn chat_item_order() {
        let mut partial = Store::empty();

        partial
            .add_account_data(proto::AccountData::test_data())
            .expect("valid account data");
        partial
            .add_recipient(proto::Recipient::test_data())
            .expect("valid recipient");
        partial
            .add_recipient(proto::Recipient::test_data_contact())
            .expect("valid recipient");

        const CHAT_IDS: std::ops::RangeInclusive<u64> = 1..=2;

        // Interleave some chat items from different chats.
        for chat_id in CHAT_IDS {
            partial
                .add_chat(proto::Chat {
                    id: chat_id,
                    ..proto::Chat::test_data()
                })
                .expect("valid chat");
        }
        for _ in 0..3 {
            for chat_id in CHAT_IDS {
                partial
                    .add_chat_item(proto::ChatItem {
                        chatId: chat_id,
                        ..proto::ChatItem::test_data()
                    })
                    .expect("valid chat item");
            }
        }

        let chat_order_indices = CompletedBackup::try_from(partial)
            .expect("valid completed backup")
            .chats
            .items
            .into_iter()
            .map(|(chat_id, items)| {
                (
                    chat_id,
                    items
                        .items
                        .into_iter()
                        .map(|item| item.total_chat_item_order_index)
                        .collect(),
                )
            })
            .collect::<HashMap<ChatId, Vec<usize>>>();

        assert_eq!(
            chat_order_indices,
            HashMap::from([(ChatId(1), vec![0, 2, 4]), (ChatId(2), vec![1, 3, 5])])
        );
    }
}
