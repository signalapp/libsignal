//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use nonzero_ext::nonzero;
use once_cell::sync::Lazy;

use crate::backup::call::CallLink;
use crate::backup::chat::chat_style::{CustomChatColor, CustomColorId};
use crate::backup::chat::PinOrder;
use crate::backup::frame::RecipientId;
use crate::backup::method::{Lookup, LookupPair};
use crate::backup::recipient::group::GroupData;
use crate::backup::recipient::{ContactData, Destination, DestinationKind, FullRecipientData};
use crate::backup::time::Timestamp;
use crate::backup::{BackupMeta, Purpose};

pub(super) struct TestContext(pub(super) BackupMeta);

impl Default for TestContext {
    fn default() -> Self {
        Self(BackupMeta::test_value())
    }
}

impl BackupMeta {
    fn test_value() -> Self {
        Self {
            backup_time: Timestamp::test_value(),
            purpose: Purpose::RemoteBackup,
            version: 0,
        }
    }
}
static SELF_RECIPIENT: Lazy<FullRecipientData> =
    Lazy::new(|| FullRecipientData::new(Destination::Self_));
static CONTACT_RECIPIENT: Lazy<FullRecipientData> =
    Lazy::new(|| FullRecipientData::new(Destination::Contact(ContactData::from_proto_test_data())));
static GROUP_RECIPIENT: Lazy<FullRecipientData> =
    Lazy::new(|| FullRecipientData::new(Destination::Group(GroupData::from_proto_test_data())));
static CALL_LINK_RECIPIENT: Lazy<FullRecipientData> =
    Lazy::new(|| FullRecipientData::new(Destination::CallLink(CallLink::from_proto_test_data())));

impl TestContext {
    pub(super) const CONTACT_ID: RecipientId = RecipientId(123456789);
    pub(super) const SELF_ID: RecipientId = RecipientId(1111111111);
    pub(super) const GROUP_ID: RecipientId = RecipientId(7000000);
    pub(super) const CALL_LINK_ID: RecipientId = RecipientId(0xCA77);
}

impl LookupPair<RecipientId, DestinationKind, FullRecipientData> for TestContext {
    fn lookup_pair<'a>(
        &'a self,
        key: &'a RecipientId,
    ) -> Option<(&'a DestinationKind, &'a FullRecipientData)> {
        match *key {
            Self::CONTACT_ID => Some((&DestinationKind::Contact, &CONTACT_RECIPIENT)),
            Self::SELF_ID => Some((&DestinationKind::Self_, &SELF_RECIPIENT)),
            Self::GROUP_ID => Some((&DestinationKind::Group, &GROUP_RECIPIENT)),
            Self::CALL_LINK_ID => Some((&DestinationKind::CallLink, &CALL_LINK_RECIPIENT)),
            _ => None,
        }
    }
}

impl Lookup<PinOrder, FullRecipientData> for TestContext {
    fn lookup(&self, key: &PinOrder) -> Option<&FullRecipientData> {
        (*key == Self::DUPLICATE_PINNED_ORDER).then_some(&SELF_RECIPIENT)
    }
}

impl AsRef<BackupMeta> for TestContext {
    fn as_ref(&self) -> &BackupMeta {
        &self.0
    }
}

impl Lookup<CustomColorId, Arc<CustomChatColor>> for TestContext {
    fn lookup<'a>(&'a self, key: &'a CustomColorId) -> Option<&'a Arc<CustomChatColor>> {
        (*key == Self::CUSTOM_CHAT_COLOR_ID).then(|| &*TEST_CUSTOM_COLOR)
    }
}

static TEST_CUSTOM_COLOR: Lazy<Arc<CustomChatColor>> =
    Lazy::new(|| Arc::new(CustomChatColor::from_proto_test_data()));

impl TestContext {
    pub(super) const DUPLICATE_PINNED_ORDER: PinOrder = PinOrder(nonzero!(183324u32));
    pub(super) const CUSTOM_CHAT_COLOR_ID: CustomColorId = CustomColorId(555);

    pub(super) fn test_recipient() -> &'static FullRecipientData {
        &SELF_RECIPIENT
    }

    pub(super) fn contact_recipient() -> &'static FullRecipientData {
        &CONTACT_RECIPIENT
    }
}

pub(super) const TEST_MESSAGE_TEXT: &str = "test message text";
