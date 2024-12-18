//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::ServiceId;
use protobuf::Enum as _;
use serde::ser::{SerializeStruct as _, SerializeTupleVariant as _};
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::backup::account_data::AccountData;
use crate::backup::call::AdHocCall;
use crate::backup::chat::group::Invitee;
use crate::backup::chat::text::{TextEffect, TextRange};
use crate::backup::chat::{ChatData, OutgoingSend};
use crate::backup::chat_folder::ChatFolder;
use crate::backup::frame::RecipientId;
use crate::backup::method::Store;
use crate::backup::notification_profile::NotificationProfile;
use crate::backup::recipient::{DistributionListItem, FullRecipientData};
use crate::backup::sticker::{PackId as StickerPackId, StickerPack};
use crate::backup::{BackupMeta, ChatsData, CompletedBackup};
use crate::proto::backup as proto;

mod unordered_list;
pub use unordered_list::UnorderedList;

/// Serializable type with a canonical representation.
#[derive(Debug, serde::Serialize)]
pub struct Backup {
    meta: BackupMeta,
    account_data: AccountData<Store>,
    recipients: UnorderedList<FullRecipientData>,
    chats: UnorderedList<ChatData<Store>>,
    ad_hoc_calls: UnorderedList<AdHocCall<FullRecipientData>>,
    pinned_chats: Vec<FullRecipientData>,
    sticker_packs: UnorderedList<(StickerPackId, StickerPack<Store>)>,
    notification_profiles: UnorderedList<NotificationProfile<FullRecipientData>>,
    chat_folders: Vec<ChatFolder<FullRecipientData>>,
}

impl Backup {
    #[cfg(feature = "json")]
    pub fn to_string_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("can't fail serialization")
    }
}

impl From<CompletedBackup<Store>> for Backup {
    fn from(value: CompletedBackup<Store>) -> Self {
        let CompletedBackup {
            meta,
            account_data,
            recipients,
            chats:
                ChatsData {
                    items,
                    pinned,
                    chat_items_count: _,
                },
            ad_hoc_calls,
            sticker_packs,
            notification_profiles,
            chat_folders,
        } = value;
        Self {
            meta,
            account_data,
            recipients: recipients.into_iter().map(|(_, v)| v).collect(),
            chats: items.into_iter().map(|(_, v)| v).collect(),
            ad_hoc_calls: ad_hoc_calls.into_iter().collect(),
            pinned_chats: pinned.into_iter().map(|(_, data)| data).collect(),
            sticker_packs: sticker_packs.into_iter().collect(),
            notification_profiles,
            chat_folders,
        }
    }
}

/// Serializes using [`ToString`].
pub(crate) fn to_string<S: Serializer>(t: &impl ToString, s: S) -> Result<S::Ok, S::Error> {
    t.to_string().serialize(s)
}

/// Serializes using [`ServiceId::service_id_string`].
pub(crate) fn service_id_as_string<S: Serializer>(
    id: &(impl Copy + Into<ServiceId>),
    serializer: S,
) -> Result<S::Ok, S::Error> {
    (*id).into().service_id_string().serialize(serializer)
}

/// Serializes using [`ServiceId::service_id_string`].
pub(crate) fn optional_service_id_as_string<S: Serializer>(
    id: &Option<(impl Copy + Into<ServiceId>)>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    (*id)
        .map(|id| id.into().service_id_string())
        .serialize(serializer)
}

/// Serializes [`protobuf::Enum`] types as strings.
pub(crate) fn enum_as_string<S: Serializer>(
    source: &impl protobuf::Enum,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    format!("{source:?}").serialize(serializer)
}

/// Serializes an optional bytestring as hex.
pub(crate) fn optional_hex<S: Serializer>(
    value: &Option<impl AsRef<[u8]>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_ref().map(hex::encode).serialize(serializer)
}

/// Serializes an optional bytestring as hex.
pub(crate) fn list_of_hex<S: Serializer>(
    value: &[impl AsRef<[u8]>],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // From the implementation of Serialize for [T],
    // https://docs.rs/serde/1.0.210/src/serde/ser/impls.rs.html#175-186
    serializer.collect_seq(value.iter().map(hex::encode))
}

pub(crate) fn backup_key_as_hex<S: Serializer>(
    value: &libsignal_account_keys::BackupKey,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    hex::encode(value.0).serialize(serializer)
}

pub(crate) fn optional_identity_key_hex<S: Serializer>(
    value: &Option<libsignal_protocol::IdentityKey>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value
        .as_ref()
        .map(|key| key.serialize())
        .serialize(serializer)
}

/// Serialization helper for [`UnorderedList`].
///
/// Like [`std::cmp::Ord`] but only for use during serialization.
pub trait SerializeOrder {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering;
}

impl SerializeOrder for ChatData<Store> {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.recipient.serialize_cmp(&other.recipient)
    }
}

impl<R> SerializeOrder for AdHocCall<R> {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl SerializeOrder for (StickerPackId, StickerPack<Store>) {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl SerializeOrder for RecipientId {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl SerializeOrder for FullRecipientData {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        use crate::backup::recipient::Destination;

        let lhs = &**self;
        let rhs = &**other;
        if std::mem::discriminant(lhs) == std::mem::discriminant(rhs) {
            match (lhs, rhs) {
                (Destination::Contact(lhs), Destination::Contact(rhs)) => (
                    &lhs.aci,
                    &lhs.pni,
                    &lhs.e164,
                    &lhs.profile_key,
                    &lhs.username,
                )
                    .cmp(&(
                        &rhs.aci,
                        &rhs.pni,
                        &rhs.e164,
                        &rhs.profile_key,
                        &rhs.username,
                    )),
                (Destination::Group(lhs), Destination::Group(rhs)) => {
                    lhs.master_key.cmp(&rhs.master_key)
                }
                (Destination::DistributionList(lhs), Destination::DistributionList(rhs)) => {
                    fn distribution_id<R>(value: &DistributionListItem<R>) -> &Uuid {
                        match value {
                            DistributionListItem::Deleted {
                                distribution_id, ..
                            } => distribution_id,
                            DistributionListItem::List {
                                distribution_id, ..
                            } => distribution_id,
                        }
                    }
                    distribution_id(lhs).cmp(distribution_id(rhs))
                }
                (Destination::CallLink(lhs), Destination::CallLink(rhs)) => {
                    lhs.root_key.cmp(&rhs.root_key)
                }
                (Destination::Self_, Destination::Self_)
                | (Destination::ReleaseNotes, Destination::ReleaseNotes) => {
                    std::cmp::Ordering::Equal
                }
                _ => unreachable!("discriminants are equal"),
            }
        } else {
            let discriminant = |value: &Destination<_>| match value {
                Destination::Self_ => 0,
                Destination::ReleaseNotes => 1,
                Destination::Contact(_) => 2,
                Destination::Group(_) => 3,
                Destination::DistributionList(_) => 4,
                Destination::CallLink(_) => 5,
            };
            discriminant(lhs).cmp(&discriminant(rhs))
        }
    }
}

impl SerializeOrder for TextRange {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Order by start, then by length...
        match (self.start, self.length).cmp(&(other.start, other.length)) {
            result @ (std::cmp::Ordering::Less | std::cmp::Ordering::Greater) => {
                return result;
            }
            std::cmp::Ordering::Equal => {}
        }
        // ...and only look at the effect if the range part is identical.
        match (&self.effect, &other.effect) {
            (TextEffect::MentionAci(left), TextEffect::MentionAci(right)) => left.cmp(right),
            (TextEffect::Style(left), TextEffect::Style(right)) => left.value().cmp(&right.value()),
            _ => {
                let discriminant = |value: &TextEffect| match value {
                    TextEffect::MentionAci(_) => 0,
                    TextEffect::Style(_) => 1,
                };
                discriminant(&self.effect).cmp(&discriminant(&other.effect))
            }
        }
    }
}

impl<R: SerializeOrder> SerializeOrder for OutgoingSend<R> {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.recipient
            .serialize_cmp(&other.recipient)
            .then_with(|| self.last_status_update.cmp(&other.last_status_update))
    }
}

impl SerializeOrder for Invitee {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.invitee_aci, self.invitee_pni, self.inviter).cmp(&(
            other.invitee_aci,
            other.invitee_pni,
            other.inviter,
        ))
    }
}

impl serde::Serialize for proto::contact_attachment::Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            givenName,
            familyName,
            prefix,
            suffix,
            middleName,
            nickname,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("Name", 6)?;
        ser.serialize_field("givenName", givenName)?;
        ser.serialize_field("familyName", familyName)?;
        ser.serialize_field("prefix", prefix)?;
        ser.serialize_field("suffix", suffix)?;
        ser.serialize_field("middleName", middleName)?;
        ser.serialize_field("nickname", nickname)?;
        ser.end()
    }
}

impl serde::Serialize for proto::contact_attachment::Phone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            value,
            type_,
            label,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("Phone", 3)?;
        ser.serialize_field("value", value)?;
        ser.serialize_field("type_", &format!("{:?}", type_))?;
        ser.serialize_field("label", label)?;
        ser.end()
    }
}

impl serde::Serialize for proto::contact_attachment::Email {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            value,
            type_,
            label,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("Email", 3)?;
        ser.serialize_field("value", value)?;
        ser.serialize_field("type_", &format!("{:?}", type_))?;
        ser.serialize_field("label", label)?;
        ser.end()
    }
}

impl serde::Serialize for proto::contact_attachment::PostalAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            type_,
            label,
            street,
            pobox,
            neighborhood,
            city,
            region,
            postcode,
            country,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("PostalAddress", 9)?;
        ser.serialize_field("type_", &format!("{:?}", type_))?;
        ser.serialize_field("label", label)?;
        ser.serialize_field("street", street)?;
        ser.serialize_field("pobox", pobox)?;
        ser.serialize_field("neighborhood", neighborhood)?;
        ser.serialize_field("city", city)?;
        ser.serialize_field("region", region)?;
        ser.serialize_field("postcode", postcode)?;
        ser.serialize_field("country", country)?;
        ser.end()
    }
}

impl serde::Serialize for proto::learned_profile_chat_update::PreviousName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            proto::learned_profile_chat_update::PreviousName::E164(e164) => {
                let mut tv = serializer.serialize_tuple_variant("PreviousName", 0, "E164", 1)?;
                tv.serialize_field(e164)?;
                tv.end()
            }
            proto::learned_profile_chat_update::PreviousName::Username(username) => {
                let mut tv =
                    serializer.serialize_tuple_variant("PreviousName", 1, "Username", 1)?;
                tv.serialize_field(username)?;
                tv.end()
            }
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::backup::frame::ChatId;
    use crate::backup::time::Timestamp;
    use crate::proto::backup as proto;

    impl proto::BackupInfo {
        fn test_data() -> Self {
            Self {
                version: 1,
                backupTimeMs: 1715636551000,
                mediaRootBackupKey: vec![0xab; libsignal_account_keys::BACKUP_KEY_LEN],
                currentAppVersion: "libsignal-testing 0.0.2".into(),
                firstAppVersion: "libsignal-testing 0.0.1".into(),
                special_fields: Default::default(),
            }
        }
    }

    fn backup_from_frames(
        frames: impl IntoIterator<Item = proto::Frame>,
    ) -> crate::CompletedBackup<Store> {
        let mut reader = crate::backup::PartialBackup::new(
            proto::BackupInfo::test_data(),
            crate::backup::Purpose::RemoteBackup,
        )
        .expect("valid metadata");
        for frame in frames {
            reader.add_frame(frame).expect("valid frame")
        }
        reader.try_into().expect("can complete")
    }

    #[test]
    fn can_serialize() {
        let backup = Backup {
            meta: BackupMeta {
                version: 1,
                backup_time: Timestamp::test_value(),
                purpose: crate::backup::Purpose::RemoteBackup,
                media_root_backup_key: libsignal_account_keys::BackupKey(
                    [0xab; libsignal_account_keys::BACKUP_KEY_LEN],
                ),
                current_app_version: "libsignal-testing 0.0.2".into(),
                first_app_version: "libsignal-testing 0.0.1".into(),
            },
            account_data: AccountData::from_proto_test_data(),
            recipients: UnorderedList::default(),
            chats: UnorderedList::default(),
            ad_hoc_calls: UnorderedList::default(),
            pinned_chats: Vec::default(),
            sticker_packs: UnorderedList::default(),
            notification_profiles: UnorderedList::default(),
            chat_folders: Vec::default(),
        };

        const EXPECTED_JSON: &str = include_str!("expected_serialized_backup.json");

        pretty_assertions::assert_eq!(
            serde_json::to_string_pretty(&backup).unwrap(),
            format!("{EXPECTED_JSON:#}")
        );
    }

    trait Renumbered {
        fn renumbered(self) -> Self;
    }

    impl Renumbered for RecipientId {
        fn renumbered(self) -> Self {
            RecipientId(1000 - self.0)
        }
    }
    impl Renumbered for ChatId {
        fn renumbered(self) -> Self {
            ChatId(1000 - self.0)
        }
    }

    fn make_contact(name: &str, index: u8) -> proto::Contact {
        proto::Contact {
            aci: Some(Uuid::from_bytes([index; 16]).as_bytes().to_vec()),
            profileGivenName: Some(name.to_owned()),
            registration: Some(proto::contact::Registration::Registered(
                proto::contact::Registered {
                    special_fields: Default::default(),
                },
            )),
            ..Default::default()
        }
    }

    fn make_chat(id: ChatId, recipient: RecipientId) -> proto::Frame {
        proto::Frame {
            item: Some(
                proto::Chat {
                    id: id.0,
                    recipientId: recipient.0,
                    ..Default::default()
                }
                .into(),
            ),
            special_fields: Default::default(),
        }
    }

    fn make_chat_item(id: ChatId, author: RecipientId, message: &'static str) -> proto::Frame {
        proto::Frame {
            item: Some(
                proto::ChatItem {
                    chatId: id.0,
                    authorId: author.0,
                    item: Some(standard_message(message).into()),
                    directionalDetails: Some(
                        proto::chat_item::IncomingMessageDetails::default().into(),
                    ),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        }
    }

    fn make_recipient(
        id: RecipientId,
        destination: &(impl Clone + Into<proto::recipient::Destination>),
    ) -> proto::Frame {
        proto::Frame {
            item: Some(
                proto::Recipient {
                    id: id.0,
                    destination: Some(destination.clone().into()),
                    special_fields: Default::default(),
                }
                .into(),
            ),
            ..Default::default()
        }
    }

    fn standard_message(text: &str) -> proto::StandardMessage {
        proto::StandardMessage {
            text: Some(proto::Text {
                body: text.to_owned(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    const FIRST_CONTACT_CHAT_ID: ChatId = ChatId(1);
    const SECOND_CONTACT_CHAT_ID: ChatId = ChatId(2);
    const GROUP_CHAT_ID: ChatId = ChatId(3);

    const FIRST_CONTACT_ID: RecipientId = RecipientId(100);
    const SECOND_CONTACT_ID: RecipientId = RecipientId(101);
    const GROUP_ID: RecipientId = RecipientId(102);
    const SELF_ID: RecipientId = RecipientId(10);

    #[test]
    fn shuffled_chats_and_recipient_ids() {
        let base = vec![crate::proto::backup::Frame {
            item: Some(proto::AccountData::test_data().into()),
            special_fields: Default::default(),
        }];

        let first_contact = make_contact("first", 1);
        let second_contact = make_contact("second", 2);

        let group = proto::recipient::Destination::Group(proto::Group {
            masterKey: [0x47; zkgroup::GROUP_MASTER_KEY_LEN].into(),
            snapshot: Some(proto::group::GroupSnapshot {
                // present but empty, technically a valid group
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });

        let chat_frames = vec![
            // Self-recipient
            make_recipient(
                SELF_ID,
                &proto::recipient::Destination::Self_(Default::default()),
            ),
            // Chat with FIRST_CONTACT
            make_recipient(FIRST_CONTACT_ID, &first_contact),
            make_chat(FIRST_CONTACT_CHAT_ID, FIRST_CONTACT_ID),
            make_chat_item(FIRST_CONTACT_CHAT_ID, FIRST_CONTACT_ID, "first message"),
            // Chat with SECOND_CONTACT
            make_recipient(SECOND_CONTACT_ID, &second_contact),
            make_chat(SECOND_CONTACT_CHAT_ID, SECOND_CONTACT_ID),
            make_chat_item(SECOND_CONTACT_CHAT_ID, SECOND_CONTACT_ID, "second message"),
            // Chat with DISTRIBUTION_LIST
            make_recipient(GROUP_ID, &group),
            make_chat(GROUP_CHAT_ID, GROUP_ID),
            make_chat_item(GROUP_CHAT_ID, FIRST_CONTACT_ID, "third message"),
        ];

        let chat_frames_reordered_and_numbered = vec![
            // Recipients first, in a different order
            make_recipient(SECOND_CONTACT_ID.renumbered(), &second_contact),
            make_recipient(FIRST_CONTACT_ID.renumbered(), &first_contact),
            make_recipient(GROUP_ID.renumbered(), &group),
            // Then the chats with those recipients
            make_chat(GROUP_CHAT_ID.renumbered(), GROUP_ID.renumbered()),
            make_chat(
                SECOND_CONTACT_CHAT_ID.renumbered(),
                SECOND_CONTACT_ID.renumbered(),
            ),
            make_chat(
                FIRST_CONTACT_CHAT_ID.renumbered(),
                FIRST_CONTACT_ID.renumbered(),
            ),
            // Self-recipient is late.
            make_recipient(
                SELF_ID.renumbered(),
                &proto::recipient::Destination::Self_(Default::default()),
            ),
            // The same messages appear in the same global order as above.
            make_chat_item(
                FIRST_CONTACT_CHAT_ID.renumbered(),
                FIRST_CONTACT_ID.renumbered(),
                "first message",
            ),
            make_chat_item(
                SECOND_CONTACT_CHAT_ID.renumbered(),
                SECOND_CONTACT_ID.renumbered(),
                "second message",
            ),
            make_chat_item(
                GROUP_CHAT_ID.renumbered(),
                FIRST_CONTACT_ID.renumbered(),
                "third message",
            ),
        ];

        let first: super::Backup =
            backup_from_frames(base.iter().cloned().chain(chat_frames)).into();
        let second: super::Backup =
            backup_from_frames(base.into_iter().chain(chat_frames_reordered_and_numbered)).into();

        assert_eq!(first.to_string_pretty(), second.to_string_pretty())
    }

    #[test]
    fn shuffled_chat_item_frames_not_equal() {
        let first_contact = make_contact("first", 1);
        let second_contact = make_contact("second", 2);

        let constant_frames = vec![
            proto::Frame {
                item: Some(proto::AccountData::test_data().into()),
                special_fields: Default::default(),
            },
            make_recipient(
                SELF_ID,
                &proto::recipient::Destination::Self_(Default::default()),
            ),
            make_recipient(FIRST_CONTACT_ID, &first_contact),
            make_chat(FIRST_CONTACT_CHAT_ID, FIRST_CONTACT_ID),
            make_recipient(SECOND_CONTACT_ID, &second_contact),
            make_chat(SECOND_CONTACT_CHAT_ID, SECOND_CONTACT_ID),
        ];

        // These chat item frames are for different chats, but their relative order
        // in the backup stream is still important.
        let chat_item_frames = vec![
            make_chat_item(FIRST_CONTACT_CHAT_ID, FIRST_CONTACT_ID, "first message"),
            make_chat_item(SECOND_CONTACT_CHAT_ID, SECOND_CONTACT_ID, "second message"),
        ];

        let with_unshuffled_frames = constant_frames
            .iter()
            .chain(&chat_item_frames)
            .cloned()
            .collect::<Vec<proto::Frame>>();

        let common_frames_len = with_unshuffled_frames.len() - chat_item_frames.len();

        let with_shuffled_frames = constant_frames
            .into_iter()
            .chain(chat_item_frames.into_iter().rev())
            .collect::<Vec<proto::Frame>>();

        // All but the chat item frames at the end should be identical.
        assert_eq!(
            &with_unshuffled_frames[..common_frames_len],
            &with_shuffled_frames[..common_frames_len]
        );
        assert_ne!(
            &with_unshuffled_frames[common_frames_len..],
            &with_shuffled_frames[common_frames_len..]
        );

        let with_unshuffled_frames: super::Backup =
            backup_from_frames(with_unshuffled_frames).into();
        let with_shuffled_frames: super::Backup = backup_from_frames(with_shuffled_frames).into();

        assert_ne!(
            with_unshuffled_frames.to_string_pretty(),
            with_shuffled_frames.to_string_pretty()
        );
    }
}
