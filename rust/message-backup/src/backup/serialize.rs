//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::ServiceId;
use serde::ser::{SerializeStruct as _, SerializeTupleVariant as _};
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::backup::account_data::AccountData;
use crate::backup::call::AdHocCall;
use crate::backup::chat::ChatData;
use crate::backup::frame::RecipientId;
use crate::backup::method::Store;
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
        } = value;
        Self {
            meta,
            account_data,
            recipients: recipients.into_values().collect(),
            chats: items.into_values().collect(),
            ad_hoc_calls: ad_hoc_calls.into_iter().collect(),
            pinned_chats: pinned.into_iter().map(|(_, data)| data).collect(),
            sticker_packs: sticker_packs.into_iter().collect(),
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

/// Serializes [`protobuf::Message`] types as hex-encoded protobuf wire format.
pub(crate) fn optional_proto_message_as_bytes<S: Serializer, M: protobuf::Message>(
    message: &Option<impl std::ops::Deref<Target = M>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    struct MessageAsHexBytes<T>(T);
    impl<T: protobuf::Message> Serialize for MessageAsHexBytes<&'_ T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            self.0
                .write_to_vec(&mut bytes)
                .map_err(<S::Error as serde::ser::Error>::custom)?;

            hex::serialize(bytes, serializer)
        }
    }

    message
        .as_deref()
        .map(MessageAsHexBytes)
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
                Destination::Contact(_) => 0,
                Destination::Group(_) => 1,
                Destination::DistributionList(_) => 2,
                Destination::Self_ => 3,
                Destination::ReleaseNotes => 4,
                Destination::CallLink(_) => 5,
            };
            discriminant(lhs).cmp(&discriminant(rhs))
        }
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
            displayName,
            special_fields: _,
        } = self;
        let mut ser = serializer.serialize_struct("Name", 6)?;
        ser.serialize_field("givenName", givenName)?;
        ser.serialize_field("familyName", familyName)?;
        ser.serialize_field("prefix", prefix)?;
        ser.serialize_field("suffix", suffix)?;
        ser.serialize_field("middleName", middleName)?;
        ser.serialize_field("displayName", displayName)?;
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

    use crate::backup::frame::ChatId;
    use crate::backup::time::Timestamp;
    use crate::proto::backup as proto;

    use super::*;

    impl proto::BackupInfo {
        fn test_data() -> Self {
            Self {
                version: 1,
                backupTimeMs: 1715636551000,
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
        );
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
            },
            account_data: AccountData::from_proto_test_data(),
            recipients: UnorderedList::default(),
            chats: UnorderedList::default(),
            ad_hoc_calls: UnorderedList::default(),
            pinned_chats: Vec::default(),
            sticker_packs: UnorderedList::default(),
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
            RecipientId(1000 + self.0)
        }
    }
    impl Renumbered for ChatId {
        fn renumbered(self) -> Self {
            ChatId(1000 + self.0)
        }
    }

    fn make_contact(name: &str, index: u8) -> proto::Contact {
        proto::Contact {
            aci: Some(Uuid::from_bytes([index; 16]).as_bytes().to_vec()),
            pni: Some(Uuid::from_bytes([index | 0xF0; 16]).as_bytes().to_vec()),
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
    const DISTRIBUTION_LIST_CHAT_ID: ChatId = ChatId(3);

    const FIRST_CONTACT_ID: RecipientId = RecipientId(100);
    const SECOND_CONTACT_ID: RecipientId = RecipientId(101);
    const DISTRIBUTION_LIST_ID: RecipientId = RecipientId(102);

    #[test]
    fn shuffled_chats_and_recipient_ids() {
        let base = vec![crate::proto::backup::Frame {
            item: Some(proto::AccountData::test_data().into()),
            special_fields: Default::default(),
        }];

        let first_contact = make_contact("first", 1);
        let second_contact = make_contact("second", 2);

        let distribution_id = Uuid::from_bytes([0xdd; 16]).as_bytes().to_vec();
        let distribution_list = |recipient_ids| {
            proto::recipient::Destination::DistributionList(proto::DistributionListItem {
                distributionId: distribution_id.clone(),
                item: Some(proto::distribution_list_item::Item::DistributionList(
                    proto::DistributionList {
                        name: "list".to_owned(),
                        memberRecipientIds: recipient_ids,
                        privacyMode: proto::distribution_list::PrivacyMode::ALL.into(),
                        ..Default::default()
                    },
                )),
                special_fields: Default::default(),
            })
        };

        let chat_frames = vec![
            // Chat with FIRST_CONTACT
            make_recipient(FIRST_CONTACT_ID, &first_contact),
            make_chat(FIRST_CONTACT_CHAT_ID, FIRST_CONTACT_ID),
            make_chat_item(FIRST_CONTACT_CHAT_ID, FIRST_CONTACT_ID, "first message"),
            // Chat with SECOND_CONTACT
            make_recipient(SECOND_CONTACT_ID, &second_contact),
            make_chat(SECOND_CONTACT_CHAT_ID, SECOND_CONTACT_ID),
            make_chat_item(SECOND_CONTACT_CHAT_ID, SECOND_CONTACT_ID, "second message"),
            // Chat with DISTRIBUTION_LIST
            make_recipient(
                DISTRIBUTION_LIST_ID,
                &distribution_list(vec![FIRST_CONTACT_ID.0, SECOND_CONTACT_ID.0]),
            ),
            make_chat(DISTRIBUTION_LIST_CHAT_ID, DISTRIBUTION_LIST_ID),
            make_chat_item(DISTRIBUTION_LIST_CHAT_ID, FIRST_CONTACT_ID, "third message"),
        ];

        let chat_frames_reordered_and_numbered = vec![
            // Recipients first, in a different order
            make_recipient(SECOND_CONTACT_ID.renumbered(), &second_contact),
            make_recipient(FIRST_CONTACT_ID.renumbered(), &first_contact),
            make_recipient(
                DISTRIBUTION_LIST_ID.renumbered(),
                &distribution_list(vec![
                    SECOND_CONTACT_ID.renumbered().0,
                    FIRST_CONTACT_ID.renumbered().0,
                ]),
            ),
            // Then the chats with those recipients
            make_chat(
                DISTRIBUTION_LIST_CHAT_ID.renumbered(),
                DISTRIBUTION_LIST_ID.renumbered(),
            ),
            make_chat(
                SECOND_CONTACT_CHAT_ID.renumbered(),
                SECOND_CONTACT_ID.renumbered(),
            ),
            make_chat(
                FIRST_CONTACT_CHAT_ID.renumbered(),
                FIRST_CONTACT_ID.renumbered(),
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
                DISTRIBUTION_LIST_CHAT_ID.renumbered(),
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
