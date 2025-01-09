//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::RefCell;
use std::collections::{hash_map, HashMap};
use std::fmt::Debug;
use std::sync::Arc;

use derive_where::derive_where;
use intmap::IntMap;
use libsignal_account_keys::BACKUP_KEY_LEN;
use libsignal_core::{Aci, Pni};

pub(crate) use crate::backup::account_data::{AccountData, AccountDataError};
use crate::backup::call::{AdHocCall, CallError};
use crate::backup::chat::chat_style::{CustomChatColor, CustomColorId};
use crate::backup::chat::{ChatData, ChatError, ChatItemData, ChatItemError, PinOrder};
use crate::backup::chat_folder::{ChatFolder, ChatFolderError};
use crate::backup::frame::{ChatId, RecipientId};
use crate::backup::hashutil::{AssumedRandomInputHasher, HashBytesAllAtOnce};
use crate::backup::method::{Lookup, LookupPair, Method};
pub use crate::backup::method::{Store, ValidateOnly};
use crate::backup::notification_profile::{NotificationProfile, NotificationProfileError};
use crate::backup::recipient::{FullRecipientData, MinimalRecipientData, RecipientError};
use crate::backup::serialize::{backup_key_as_hex, SerializeOrder, UnorderedList};
use crate::backup::sticker::{PackId as StickerPackId, StickerPack, StickerPackError};
use crate::backup::time::{
    ReportUnusualTimestamp, Timestamp, TimestampError, TimestampIssue, UnusualTimestampTracker,
};
use crate::proto::backup as proto;
use crate::proto::backup::frame::Item as FrameItem;

mod account_data;
mod call;
mod chat;
mod chat_folder;
mod file;
mod frame;
mod hashutil;
pub(crate) mod method;
mod notification_profile;
mod recipient;
pub mod serialize;
mod sticker;
mod time;

#[cfg(test)]
mod testutil;

#[cfg(feature = "scramble")]
pub(crate) use crate::backup::recipient::MY_STORY_UUID;

pub trait ReferencedTypes {
    /// Recorded information from a [`proto::Recipient`].
    type RecipientData: Debug
        + AsRef<MinimalRecipientData>
        + From<recipient::Destination<Self::RecipientReference>>;
    /// Resolved data for a recipient in a non-`proto::Recipient` message.
    type RecipientReference: Clone + Debug + serde::Serialize + SerializeOrder;

    /// Recorded information from a [`proto::chat_style::CustomChatColor`].
    type CustomColorData: Debug + From<CustomChatColor> + serde::Serialize;
    /// Resolved data for a custom color in a non-`CustomChatColor` message.
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

    fn is_same_reference(left: &Self::RecipientReference, right: &Self::RecipientReference)
        -> bool;
}

pub struct PartialBackup<M: Method + ReferencedTypes> {
    meta: BackupMeta,
    account_data: Option<AccountData<M>>,
    recipients: IntMap<RecipientId, M::RecipientData>,
    chats: ChatsData<M>,
    ad_hoc_calls: M::List<AdHocCall<M::RecipientReference>>,
    sticker_packs: HashMap<StickerPackId, StickerPack<M>>,
    notification_profiles: UnorderedList<NotificationProfile<M::RecipientReference>>,
    chat_folders: Vec<ChatFolder<M::RecipientReference>>,
    /// Stored here so PartialBackup can be the only context necessary for processing backup frames.
    unusual_timestamp_tracker: RefCell<UnusualTimestampTracker>,
}

#[derive_where(Debug)]
pub struct CompletedBackup<M: Method + ReferencedTypes> {
    meta: BackupMeta,
    account_data: AccountData<M>,
    recipients: IntMap<RecipientId, M::RecipientData>,
    chats: ChatsData<M>,
    ad_hoc_calls: M::List<AdHocCall<M::RecipientReference>>,
    sticker_packs: HashMap<StickerPackId, StickerPack<M>>,
    notification_profiles: UnorderedList<NotificationProfile<M::RecipientReference>>,
    chat_folders: Vec<ChatFolder<M::RecipientReference>>,
}

pub type Backup = CompletedBackup<Store>;

#[derive_where(Debug, Default)]
struct ChatsData<M: Method + ReferencedTypes> {
    items: IntMap<ChatId, ChatData<M>>,
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
    /// The key used to encrypt and upload media associated with this backup.
    #[serde(serialize_with = "backup_key_as_hex")]
    pub media_root_backup_key: libsignal_account_keys::BackupKey,
    /// The app version that made the backup.
    ///
    /// Omitted from the canonical backup string, so that subsequent backups can be compared.
    #[serde(skip)]
    pub current_app_version: String,
    /// The app version the user first registered on.
    pub first_app_version: String,
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
#[cfg_attr(test, derive(PartialEq))]
pub enum CompletionError {
    /// no AccountData frames found
    MissingAccountData,
    /// no ALL ChatFolder found
    MissingAllChatFolder,
    /// multiple ALL ChatFolders found
    DuplicateAllChatFolder,
    /// no Self recipient found
    MissingSelfRecipient,
    /// {0:?} and {1:?} have the same phone number
    DuplicateContactE164(RecipientId, RecipientId),
    /// {0:?} and {1:?} have the same ACI
    DuplicateContactAci(RecipientId, RecipientId),
    /// {0:?} and {1:?} have the same PNI
    DuplicateContactPni(RecipientId, RecipientId),
    /// {0:?} and {1:?} have the same group master key
    DuplicateGroupMasterKey(RecipientId, RecipientId),
    /// {0:?} and {1:?} have the same distribution list ID
    DuplicateDistributionListId(RecipientId, RecipientId),
    /// {0:?} and {1:?} have the same call link root key
    DuplicateCallLinkRootKey(RecipientId, RecipientId),
    /// {0:?} and {1:?} both represent the Self recipient
    DuplicateSelfRecipient(RecipientId, RecipientId),
    /// {0:?} and {1:?} both represent the release notes channel
    DuplicateReleaseNotesRecipient(RecipientId, RecipientId),
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
            notification_profiles,
            chat_folders,
            unusual_timestamp_tracker: _,
        } = value;

        let account_data = account_data.ok_or(CompletionError::MissingAccountData)?;

        if !chat_folders.is_empty() {
            match chat_folders
                .iter()
                .filter(|folder| matches!(folder, ChatFolder::All))
                .count()
            {
                0 => Err(CompletionError::MissingAllChatFolder),
                1 => Ok(()),
                _ => Err(CompletionError::DuplicateAllChatFolder),
            }?;
        }

        Self::check_for_duplicate_recipients(&recipients)?;

        Ok(CompletedBackup {
            meta,
            account_data,
            recipients,
            chats,
            ad_hoc_calls,
            sticker_packs,
            notification_profiles,
            chat_folders,
        })
    }
}

impl<M: Method + ReferencedTypes> CompletedBackup<M> {
    /// One specific check during the conversion from PartialBackup to CompletedBackup.
    ///
    /// This check could be implemented as part of [`PartialBackup::add_recipient`] instead, and
    /// indeed that would have some advantages in simplicity. However, we can't avoid reallocation
    /// costs in that case.
    fn check_for_duplicate_recipients(
        recipients: &IntMap<RecipientId, M::RecipientData>,
    ) -> Result<(), CompletionError> {
        /// Recipients aren't stored in order, but we can at least at least *pretend* we visit lower
        /// IDs before higher ones.
        ///
        /// This is better for testing, but still doesn't guarantee deterministic output if *three*
        /// (or more) recipients share identifiers.
        #[inline]
        fn sort_recipient_ids(id1: RecipientId, id2: RecipientId) -> [RecipientId; 2] {
            // TODO: Replace with std::cmp::minmax_by_key when that gets stabilized.
            // Meanwhile this shape is load-bearing for performance (anything
            // "sort"-related seems to not get optimized all the way away, possibly
            // because of the array shape).
            if id1.0 > id2.0 {
                [id2, id1]
            } else {
                [id1, id2]
            }
        }

        /// Inserts a value into a map if the key is not already present, or throws an error
        /// containing the new and old value if it is.
        fn insert_or_error<K: std::cmp::Eq + std::hash::Hash, S: std::hash::BuildHasher>(
            map: &mut HashMap<K, RecipientId, S>,
            key: Option<impl Into<K>>,
            id: RecipientId,
            error: impl Fn(RecipientId, RecipientId) -> CompletionError,
        ) -> Result<(), CompletionError> {
            if let Some(key) = key {
                match map.entry(key.into()) {
                    hash_map::Entry::Occupied(entry) => {
                        let [id1, id2] = sort_recipient_ids(*entry.get(), id);
                        return Err(error(id1, id2));
                    }
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert(id);
                    }
                }
            }
            Ok(())
        }

        // Preallocate maps as if every recipient is a contact, or a group, or...etc, with
        // reasonable limits. We want to avoid rehashing costs if possible, but we also don't want
        // to allocate *too* much memory up front. Most users will have many many recipients,
        // followed by groups and perhaps call links, and finally custom distribution lists. In the
        // worst case, these preallocations won't be big enough and the tables will have to grow as
        // we iterate.

        const HIGH_BUT_REASONABLE_NUMBER_OF_CONTACTS: usize = 2500;
        const HIGH_BUT_REASONABLE_NUMBER_OF_GROUPS: usize = 1000;
        const HIGH_BUT_REASONABLE_NUMBER_OF_DISTRIBUTION_LISTS: usize = 100;
        const HIGH_BUT_REASONABLE_NUMBER_OF_CALL_LINKS: usize = 1000;

        // Approximate the memory usage if every one of the maps below is maxed out. This is only
        // meant to be a ballpark bound, and of course it's possible a backup exceeds these limits
        // anyway, but we want to make sure we don't allocate *too* much extra memory up front.
        static_assertions::const_assert!(
            HIGH_BUT_REASONABLE_NUMBER_OF_CONTACTS * std::mem::size_of::<(u64, RecipientId)>()
                + HIGH_BUT_REASONABLE_NUMBER_OF_CONTACTS
                    * std::mem::size_of::<(Aci, RecipientId)>()
                + HIGH_BUT_REASONABLE_NUMBER_OF_CONTACTS
                    * std::mem::size_of::<(Pni, RecipientId)>()
                + HIGH_BUT_REASONABLE_NUMBER_OF_GROUPS
                    * std::mem::size_of::<(zkgroup::GroupMasterKeyBytes, RecipientId)>()
                + HIGH_BUT_REASONABLE_NUMBER_OF_DISTRIBUTION_LISTS
                    * std::mem::size_of::<(uuid::Uuid, RecipientId)>()
                + HIGH_BUT_REASONABLE_NUMBER_OF_CALL_LINKS
                    * std::mem::size_of::<(call::CallLinkRootKey, RecipientId)>()
                < 250_000,
        );

        let mut e164s = IntMap::<u64, RecipientId>::with_capacity(
            recipients.len().min(HIGH_BUT_REASONABLE_NUMBER_OF_CONTACTS),
        );
        let mut acis = AssumedRandomInputHasher::map_with_capacity::<Aci, RecipientId>(
            recipients.len().min(HIGH_BUT_REASONABLE_NUMBER_OF_CONTACTS),
        );
        let mut pnis = AssumedRandomInputHasher::map_with_capacity::<Pni, RecipientId>(
            recipients.len().min(HIGH_BUT_REASONABLE_NUMBER_OF_CONTACTS),
        );
        let mut group_master_keys =
            AssumedRandomInputHasher::map_with_capacity::<
                HashBytesAllAtOnce<zkgroup::GroupMasterKeyBytes>,
                RecipientId,
            >(recipients.len().min(HIGH_BUT_REASONABLE_NUMBER_OF_GROUPS));
        let mut distribution_ids = AssumedRandomInputHasher::map_with_capacity::<
            HashBytesAllAtOnce<uuid::Bytes>,
            RecipientId,
        >(
            recipients
                .len()
                .min(HIGH_BUT_REASONABLE_NUMBER_OF_DISTRIBUTION_LISTS),
        );
        let mut self_recipient = None;
        let mut release_notes_recipient = None;
        let mut call_link_root_keys = AssumedRandomInputHasher::map_with_capacity::<
            HashBytesAllAtOnce<call::CallLinkRootKey>,
            RecipientId,
        >(
            recipients
                .len()
                .min(HIGH_BUT_REASONABLE_NUMBER_OF_CALL_LINKS),
        );

        for (id, recipient) in recipients.iter() {
            match recipient.as_ref() {
                MinimalRecipientData::Contact { e164, aci, pni } => {
                    // We can't use insert_or_throw_error for `e164s` because it's an IntMap.
                    // Here's an inlined copy:
                    if let Some(e164) = *e164 {
                        match e164s.entry(e164.into()) {
                            intmap::Entry::Occupied(entry) => {
                                let [id1, id2] = sort_recipient_ids(*entry.get(), id);
                                return Err(CompletionError::DuplicateContactE164(id1, id2));
                            }
                            intmap::Entry::Vacant(entry) => {
                                entry.insert(id);
                            }
                        }
                    }
                    insert_or_error(&mut acis, *aci, id, CompletionError::DuplicateContactAci)?;
                    insert_or_error(&mut pnis, *pni, id, CompletionError::DuplicateContactPni)?;
                }
                MinimalRecipientData::Group { master_key } => {
                    insert_or_error(
                        &mut group_master_keys,
                        Some(*master_key),
                        id,
                        CompletionError::DuplicateGroupMasterKey,
                    )?;
                }
                MinimalRecipientData::DistributionList { distribution_id } => {
                    insert_or_error(
                        &mut distribution_ids,
                        Some(*distribution_id.as_bytes()),
                        id,
                        CompletionError::DuplicateDistributionListId,
                    )?;
                }
                MinimalRecipientData::Self_ => {
                    if let Some(previous) = self_recipient {
                        let [id1, id2] = sort_recipient_ids(previous, id);
                        return Err(CompletionError::DuplicateSelfRecipient(id1, id2));
                    }
                    self_recipient = Some(id);
                }
                MinimalRecipientData::ReleaseNotes => {
                    if let Some(previous) = release_notes_recipient {
                        let [id1, id2] = sort_recipient_ids(previous, id);
                        return Err(CompletionError::DuplicateReleaseNotesRecipient(id1, id2));
                    }
                    release_notes_recipient = Some(id);
                }
                MinimalRecipientData::CallLink { root_key } => {
                    insert_or_error(
                        &mut call_link_root_keys,
                        Some(*root_key),
                        id,
                        CompletionError::DuplicateCallLinkRootKey,
                    )?;
                }
            }
        }

        if self_recipient.is_none() {
            return Err(CompletionError::MissingSelfRecipient);
        }

        Ok(())
    }
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum ValidationError {
    /// Frame.item is a oneof but has no value
    EmptyFrame,
    /// BackupInfo error: {0}
    BackupInfoError(#[from] MetadataError),
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
    /// {0}
    NotificationProfileError(#[from] NotificationProfileError),
    /// {0}
    ChatFolderError(#[from] ChatFolderError),
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
trait TryFromWith<T, C: ?Sized>: Sized {
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
trait TryIntoWith<T, C: ?Sized>: Sized {
    type Error;

    /// Uses additional context to convert `self` into an instance of `T`.
    ///
    /// If the lookup fails, an instance of `Self::Error` is returned.
    fn try_into_with(self, context: &C) -> Result<T, Self::Error>;
}

impl<A, B: TryFromWith<A, C>, C: ?Sized> TryIntoWith<B, C> for A {
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

    fn is_same_reference(
        left: &Self::RecipientReference,
        right: &Self::RecipientReference,
    ) -> bool {
        left.is_same_reference(right)
    }
}

impl ReferencedTypes for ValidateOnly {
    type RecipientReference = RecipientId;
    type RecipientData = MinimalRecipientData;

    /// No need to keep any data for colors.
    type CustomColorData = ();
    type CustomColorReference = CustomColorId;

    #[inline]
    fn color_reference<'a>(
        id: &'a CustomColorId,
        _data: &'a Self::CustomColorData,
    ) -> &'a Self::CustomColorReference {
        id
    }

    #[inline]
    fn recipient_reference<'a>(
        id: &'a RecipientId,
        _data: &'a Self::RecipientData,
    ) -> &'a Self::RecipientReference {
        id
    }

    #[inline]
    fn is_same_reference(
        left: &Self::RecipientReference,
        right: &Self::RecipientReference,
    ) -> bool {
        left == right
    }
}

/// recipient {0:?} error: {1}
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub struct RecipientFrameError(RecipientId, RecipientError);

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum MetadataError {
    /// invalid mediaRootBackupKey (expected {BACKUP_KEY_LEN:?} bytes, got {0:?})
    InvalidMediaRootBackupKey(usize),
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl PartialBackup<ValidateOnly> {
    pub fn new_validator(
        value: proto::BackupInfo,
        purpose: Purpose,
    ) -> Result<Self, ValidationError> {
        Self::new(value, purpose)
    }
}

impl PartialBackup<Store> {
    pub fn new_store(value: proto::BackupInfo, purpose: Purpose) -> Result<Self, ValidationError> {
        Self::new(value, purpose)
    }
}

impl<M: Method + ReferencedTypes> PartialBackup<M> {
    pub fn new(value: proto::BackupInfo, purpose: Purpose) -> Result<Self, ValidationError> {
        let proto::BackupInfo {
            version,
            backupTimeMs,
            mediaRootBackupKey,
            currentAppVersion,
            firstAppVersion,
            special_fields: _,
        } = value;

        let unusual_timestamp_tracker: RefCell<UnusualTimestampTracker> = Default::default();

        let media_root_backup_key = libsignal_account_keys::BackupKey(
            mediaRootBackupKey
                .as_slice()
                .try_into()
                .map_err(|_| MetadataError::InvalidMediaRootBackupKey(mediaRootBackupKey.len()))?,
        );

        let meta = BackupMeta {
            version,
            backup_time: Timestamp::from_millis(
                backupTimeMs,
                "BackupInfo.backupTimeMs",
                &unusual_timestamp_tracker,
            )
            .map_err(MetadataError::from)?,
            media_root_backup_key,
            current_app_version: currentAppVersion,
            first_app_version: firstAppVersion,
            purpose,
        };

        Ok(Self {
            meta,
            account_data: None,
            recipients: Default::default(),
            chats: Default::default(),
            ad_hoc_calls: Default::default(),
            sticker_packs: Default::default(),
            notification_profiles: Default::default(),
            chat_folders: Default::default(),
            unusual_timestamp_tracker,
        })
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
            FrameItem::NotificationProfile(notification_profile) => self
                .add_notification_profile(notification_profile)
                .map_err(Into::into),
            FrameItem::ChatFolder(chat_folder) => {
                self.add_chat_folder(chat_folder).map_err(Into::into)
            }
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
        let account_data = account_data.try_into_with(self)?;
        self.account_data = Some(account_data);
        Ok(())
    }

    fn add_recipient(&mut self, recipient: proto::Recipient) -> Result<(), RecipientFrameError> {
        let id = recipient.id();
        let err_with_id = |e| RecipientFrameError(id, e);
        if id == RecipientId(0) {
            return Err(err_with_id(RecipientError::InvalidId));
        }

        let recipient =
            recipient::Destination::try_from_with(recipient, self).map_err(err_with_id)?;

        match self.recipients.entry(id) {
            intmap::Entry::Occupied(_) => Err(err_with_id(RecipientError::DuplicateRecipient)),
            intmap::Entry::Vacant(v) => {
                let _ = v.insert(recipient.into());
                Ok(())
            }
        }
    }

    fn add_chat(&mut self, chat: proto::Chat) -> Result<(), ChatFrameError> {
        let id = chat.id();
        let err_with_id = |e| ChatFrameError(id, e);
        if id == ChatId(0) {
            return Err(err_with_id(ChatError::InvalidId));
        }

        let chat: ChatData<M> = chat.try_into_with(self).map_err(err_with_id)?;
        self.chats.add_chat(id, chat)?;
        Ok(())
    }

    fn add_chat_item(&mut self, chat_item: proto::ChatItem) -> Result<(), ValidationError> {
        let chat_id = ChatId(chat_item.chatId);
        let raw_timestamp = chat_item.dateSent;

        let chat_item_data = chat_item
            .try_into_with(self)
            .map_err(|error: ChatItemError| {
                ChatFrameError(
                    chat_id,
                    ChatError::ChatItem {
                        raw_timestamp,
                        error,
                    },
                )
            })?;

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

    fn add_notification_profile(
        &mut self,
        notification_profile: proto::NotificationProfile,
    ) -> Result<(), ValidationError> {
        let profile = notification_profile.try_into_with(self)?;
        self.notification_profiles.0.push(profile);
        Ok(())
    }

    fn add_chat_folder(&mut self, chat_folder: proto::ChatFolder) -> Result<(), ValidationError> {
        let folder = chat_folder.try_into_with(self)?;
        self.chat_folders.push(folder);
        Ok(())
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
            intmap::Entry::Occupied(_) => Err(ChatFrameError(id, ChatError::DuplicateId)),
            intmap::Entry::Vacant(v) => {
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

        let wrap_error = |error| {
            ChatFrameError(
                chat_id,
                ChatError::ChatItem {
                    raw_timestamp: item.sent_at.as_millis(),
                    error,
                },
            )
        };

        let chat_data = items
            .get_mut(chat_id)
            .ok_or_else(|| wrap_error(ChatItemError::NoChatForItem))?;

        item.validate_chat_recipient(&chat_data.recipient, &chat_data.cached_recipient_info)
            .map_err(wrap_error)?;

        item.total_chat_item_order_index = *chat_items_count;

        chat_data.items.extend([item]);

        *chat_items_count += 1;

        Ok(())
    }
}

impl<M: Method + ReferencedTypes>
    LookupPair<RecipientId, MinimalRecipientData, M::RecipientReference> for PartialBackup<M>
{
    fn lookup_pair<'a>(
        &'a self,
        key: &'a RecipientId,
    ) -> Option<(&'a MinimalRecipientData, &'a M::RecipientReference)> {
        self.recipients
            .get(*key)
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

impl<M: Method + ReferencedTypes> ReportUnusualTimestamp for PartialBackup<M> {
    #[track_caller]
    fn report(&self, since_epoch: u64, context: &'static str, issue: TimestampIssue) {
        self.unusual_timestamp_tracker
            .report(since_epoch, context, issue);
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

pub enum ColorError {
    NotOpaque(u32),
}

#[derive(Copy, Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(transparent)]
pub struct Color(u32);

impl TryFrom<u32> for Color {
    type Error = ColorError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >> 24 != 0xFF {
            return Err(ColorError::NotOpaque(value));
        }
        Ok(Self(value))
    }
}

struct InvalidAci;

fn uuid_bytes_to_aci(bytes: Vec<u8>) -> Result<Aci, InvalidAci> {
    bytes
        .try_into()
        .map(Aci::from_uuid_bytes)
        .map_err(|_| InvalidAci)
}

/// Hint for processing a collection that's usually empty.
///
/// This saves a small amount of time by not setting up an iteration loop in `collect` only to throw
/// it away.
fn likely_empty<I, T: Default, E>(
    input: Vec<I>,
    process: impl FnOnce(std::vec::IntoIter<I>) -> Result<T, E>,
) -> Result<T, E> {
    if input.is_empty() {
        Ok(T::default())
    } else {
        process(input.into_iter())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use assert_matches::assert_matches;
    use test_case::{test_case, test_matrix};

    use super::*;

    impl proto::Chat {
        pub(super) const TEST_ID: u64 = 22222;
        pub(crate) fn test_data() -> Self {
            Self {
                id: Self::TEST_ID,
                recipientId: proto::Recipient::test_data_contact().id,
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
            let proto = proto::BackupInfo {
                mediaRootBackupKey: vec![0; BACKUP_KEY_LEN],
                ..Default::default()
            };
            PartialBackup::new(proto, Purpose::RemoteBackup).expect("valid")
        }

        fn fake() -> PartialBackup<Self> {
            Self::fake_with([
                proto::Recipient::test_data_contact().into(),
                proto::Chat::test_data().into(),
                proto::Recipient::test_data().into(),
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

    #[test_case(ValidateOnly::empty())]
    #[test_case(Store::empty())]
    fn rejects_missing_account_data<M: Method + ReferencedTypes>(partial: PartialBackup<M>) {
        assert_matches!(
            CompletedBackup::try_from(partial),
            Err(CompletionError::MissingAccountData)
        );
    }

    #[test_case(ValidateOnly::empty())]
    #[test_case(Store::empty())]
    fn rejects_missing_all_folder<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_frame_item(proto::AccountData::test_data().into())
            .expect("accepts AccountData");
        partial
            .add_frame_item(proto::Recipient::test_data_contact().into())
            .expect("accepts Contact");
        partial
            .add_frame_item(FrameItem::ChatFolder(proto::ChatFolder::test_data()))
            .expect("accepts ChatFolder");

        assert_matches!(
            CompletedBackup::try_from(partial),
            Err(CompletionError::MissingAllChatFolder)
        );
    }

    #[test_case(ValidateOnly::empty())]
    #[test_case(Store::empty())]
    fn allows_lone_all_folder<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_frame_item(proto::AccountData::test_data().into())
            .expect("accepts AccountData");
        partial
            .add_recipient(proto::Recipient::test_data())
            .expect("self recipient");
        partial
            .add_frame_item(FrameItem::ChatFolder(proto::ChatFolder::all_folder_data()))
            .expect("accepts ChatFolder");

        assert_matches!(CompletedBackup::try_from(partial), Ok(_));
    }

    #[test_case(ValidateOnly::empty())]
    #[test_case(Store::empty())]
    fn rejects_duplicate_all_folder<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_frame_item(proto::AccountData::test_data().into())
            .expect("accepts AccountData");
        partial
            .add_frame_item(FrameItem::ChatFolder(proto::ChatFolder::all_folder_data()))
            .expect("accepts ChatFolder");
        partial
            .add_frame_item(FrameItem::ChatFolder(proto::ChatFolder::all_folder_data()))
            .expect("accepts ChatFolder");

        assert_matches!(
            CompletedBackup::try_from(partial),
            Err(CompletionError::DuplicateAllChatFolder)
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

        const GROUP_ID: u64 = 200;
        partial
            .add_recipient(proto::Recipient {
                id: GROUP_ID,
                destination: proto::recipient::Destination::Group(proto::Group {
                    masterKey: [0x47; zkgroup::GROUP_MASTER_KEY_LEN].into(),
                    snapshot: Some(proto::group::GroupSnapshot {
                        // present but empty, technically a valid group
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .expect("valid group");

        const CHAT_IDS: std::ops::RangeInclusive<u64> = 1..=2;

        // Interleave some chat items from different chats.
        // Yes, we shouldn't have multiple chats for the same recipient,
        // but the validator doesn't check that because it's not going to happen by accident.
        for chat_id in CHAT_IDS {
            partial
                .add_chat(proto::Chat {
                    id: chat_id,
                    recipientId: GROUP_ID,
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
                    chat_id.0,
                    items
                        .items
                        .into_iter()
                        .map(|item| item.total_chat_item_order_index)
                        .collect(),
                )
            })
            .collect::<HashMap<u64, Vec<usize>>>();

        assert_eq!(
            chat_order_indices,
            HashMap::from([(1, vec![0, 2, 4]), (2, vec![1, 3, 5])])
        );
    }

    #[test_matrix(
        [ValidateOnly::empty(), Store::empty()],
        [
            (CompletionError::DuplicateContactAci, |x| {
                x.aci = Some(proto::Contact::TEST_ACI.into());
            }),
            (CompletionError::DuplicateContactPni, |x| {
                x.pni = Some(proto::Contact::TEST_PNI.into());
            }),
            (CompletionError::DuplicateContactE164, |x| {
                x.e164 = Some(proto::Contact::TEST_E164.into());
            }),
        ]
    )]
    fn duplicate_contact_id<M: Method + ReferencedTypes>(
        mut partial: PartialBackup<M>,
        (expected_error, fill_in_field): (
            impl Fn(RecipientId, RecipientId) -> CompletionError,
            impl Fn(&mut proto::Contact),
        ),
    ) {
        partial
            .add_account_data(proto::AccountData::test_data())
            .expect("valid account data");

        let mut first_contact = proto::Recipient::test_data_contact();
        first_contact.id = 10;
        fill_in_field(first_contact.mut_contact());

        partial
            .add_recipient(first_contact)
            .expect("valid recipient");

        let mut second_contact = proto::Recipient::test_data_contact();
        second_contact.id = 20;
        // Give it a different ACI by default.
        second_contact.mut_contact().aci = Some(uuid::Uuid::new_v4().as_bytes().to_vec());
        fill_in_field(second_contact.mut_contact());

        partial
            .add_recipient(second_contact)
            .expect("valid recipient");

        assert_eq!(
            CompletedBackup::try_from(partial).expect_err("should have failed"),
            expected_error(RecipientId(10), RecipientId(20)),
        );
    }

    #[test_matrix(
        [ValidateOnly::empty(), Store::empty()],
        [
            (CompletionError::DuplicateGroupMasterKey, proto::Group::test_data().into()),
            (CompletionError::DuplicateDistributionListId, proto::DistributionListItem::test_data().into()),
            (CompletionError::DuplicateCallLinkRootKey, proto::recipient::Destination::CallLink(proto::CallLink::test_data())),
            (CompletionError::DuplicateSelfRecipient, proto::recipient::Destination::Self_(Default::default())),
            (CompletionError::DuplicateReleaseNotesRecipient, proto::recipient::Destination::ReleaseNotes(Default::default())),
        ]
    )]
    fn duplicate_non_contact_recipient<M: Method + ReferencedTypes>(
        mut partial: PartialBackup<M>,
        (expected_error, destination): (
            impl Fn(RecipientId, RecipientId) -> CompletionError,
            proto::recipient::Destination,
        ),
    ) {
        partial
            .add_account_data(proto::AccountData::test_data())
            .expect("valid account data");
        partial
            .add_recipient(proto::Recipient::test_data_contact())
            .expect("valid contact");

        let first_recipient = proto::Recipient {
            id: 10,
            destination: Some(destination),
            ..Default::default()
        };

        partial
            .add_recipient(first_recipient.clone())
            .expect("valid recipient");

        let second_recipient = proto::Recipient {
            id: 20,
            ..first_recipient
        };

        partial
            .add_recipient(second_recipient)
            .expect("valid recipient");

        assert_eq!(
            CompletedBackup::try_from(partial).expect_err("should have failed"),
            expected_error(RecipientId(10), RecipientId(20)),
        );
    }

    #[test_case(ValidateOnly::empty())]
    #[test_case(Store::empty())]
    fn pni_matching_aci_is_okay<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_account_data(proto::AccountData::test_data())
            .expect("valid account data");

        partial
            .add_recipient(proto::Recipient::test_data())
            .expect("self recipient");

        let mut first_contact = proto::Recipient::test_data_contact();
        first_contact.id = 10;

        partial
            .add_recipient(first_contact)
            .expect("valid recipient");

        let mut second_contact = proto::Recipient::test_data_contact();
        second_contact.id = 20;
        // Move the ACI over to the PNI, and provide a new ACI.
        second_contact.mut_contact().pni = second_contact.mut_contact().aci.take();
        second_contact.mut_contact().aci = Some(uuid::Uuid::new_v4().as_bytes().to_vec());

        partial
            .add_recipient(second_contact)
            .expect("valid recipient");

        CompletedBackup::try_from(partial).expect("ACI and PNI are different namespaces");
    }

    #[test_matrix([ValidateOnly::empty(), Store::empty()])]
    fn missing_self<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_account_data(proto::AccountData::test_data())
            .expect("valid account data");
        assert_matches!(
            CompletedBackup::try_from(partial),
            Err(CompletionError::MissingSelfRecipient)
        );
    }

    #[test_matrix([ValidateOnly::empty(), Store::empty()])]
    fn zero_recipient_id<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_account_data(proto::AccountData::test_data())
            .expect("valid account data");

        let mut contact = proto::Recipient::test_data_contact();
        contact.id = 0;

        assert_matches!(
            partial.add_recipient(contact),
            Err(RecipientFrameError(
                RecipientId(0),
                RecipientError::InvalidId
            ))
        );
    }

    #[test_matrix([ValidateOnly::empty(), Store::empty()])]
    fn zero_chat_id<M: Method + ReferencedTypes>(mut partial: PartialBackup<M>) {
        partial
            .add_account_data(proto::AccountData::test_data())
            .expect("valid account data");

        partial
            .add_recipient(proto::Recipient::test_data_contact())
            .expect("valid recipient");

        let mut chat = proto::Chat::test_data();
        chat.id = 0;

        assert_matches!(
            partial.add_chat(chat),
            Err(ChatFrameError(ChatId(0), ChatError::InvalidId))
        );
    }
}
