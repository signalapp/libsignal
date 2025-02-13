//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::{Arc, LazyLock};

use super::recipient::MinimalRecipientData;
use crate::backup::call::CallLink;
use crate::backup::chat::chat_style::{CustomChatColor, CustomColorId};
use crate::backup::chat::PinOrder;
use crate::backup::frame::RecipientId;
use crate::backup::method::{Lookup, LookupPair};
use crate::backup::recipient::group::GroupData;
use crate::backup::recipient::{self, ContactData, Destination, FullRecipientData};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampIssue};
use crate::backup::{BackupMeta, Purpose};
use crate::proto::backup as proto;

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
            media_root_backup_key: libsignal_account_keys::BackupKey(
                [0xab; libsignal_account_keys::BACKUP_KEY_LEN],
            ),
            version: 0,
            current_app_version: "libsignal-testing 0.0.2".into(),
            first_app_version: "libsignal-testing 0.0.1".into(),
        }
    }
}
static SELF_RECIPIENT: LazyLock<FullRecipientData> =
    LazyLock::new(|| FullRecipientData::new(Destination::Self_));
static CONTACT_RECIPIENT: LazyLock<FullRecipientData> = LazyLock::new(|| {
    FullRecipientData::new(Destination::Contact(ContactData::from_proto_test_data()))
});
static E164_ONLY_RECIPIENT: LazyLock<FullRecipientData> = LazyLock::new(|| {
    FullRecipientData::new(Destination::Contact(ContactData {
        aci: None,
        pni: None,
        profile_key: None,
        username: None,
        registration: recipient::Registration::Registered,
        e164: Some(proto::Contact::TEST_E164),
        blocked: false,
        visibility: Default::default(),
        profile_sharing: false,
        profile_given_name: None,
        profile_family_name: None,
        hide_story: false,
        identity_key: None,
        identity_state: Default::default(),
        nickname: None,
        system_given_name: "".to_owned(),
        system_family_name: "".to_owned(),
        system_nickname: "".to_owned(),
        note: "".into(),
    }))
});
static PNI_ONLY_RECIPIENT: LazyLock<FullRecipientData> = LazyLock::new(|| {
    FullRecipientData::new(Destination::Contact(ContactData {
        aci: None,
        pni: Some(libsignal_core::Pni::from_uuid_bytes(
            proto::Contact::TEST_PNI,
        )),
        profile_key: None,
        username: None,
        registration: recipient::Registration::Registered,
        e164: None,
        blocked: false,
        visibility: Default::default(),
        profile_sharing: false,
        profile_given_name: None,
        profile_family_name: None,
        hide_story: false,
        identity_key: None,
        identity_state: Default::default(),
        system_given_name: "".to_owned(),
        system_family_name: "".to_owned(),
        system_nickname: "".to_owned(),
        nickname: None,
        note: "".into(),
    }))
});
static GROUP_RECIPIENT: LazyLock<FullRecipientData> =
    LazyLock::new(|| FullRecipientData::new(Destination::Group(GroupData::from_proto_test_data())));
static CALL_LINK_RECIPIENT: LazyLock<FullRecipientData> = LazyLock::new(|| {
    FullRecipientData::new(Destination::CallLink(CallLink::from_proto_test_data()))
});
static RELEASE_NOTES_RECIPIENT: LazyLock<FullRecipientData> =
    LazyLock::new(|| FullRecipientData::new(Destination::ReleaseNotes));

impl TestContext {
    pub(super) const CONTACT_ID: RecipientId = RecipientId(123456789);
    pub(super) const SELF_ID: RecipientId = RecipientId(1111111111);
    pub(super) const E164_ONLY_ID: RecipientId = RecipientId(164);
    pub(super) const PNI_ONLY_ID: RecipientId = RecipientId(6000000);
    pub(super) const GROUP_ID: RecipientId = RecipientId(7000000);
    pub(super) const CALL_LINK_ID: RecipientId = RecipientId(0xCA77);
    pub(super) const RELEASE_NOTES_ID: RecipientId = RecipientId(9000);
    pub(super) const NONEXISTENT_ID: RecipientId = RecipientId(9999);
}

impl LookupPair<RecipientId, MinimalRecipientData, FullRecipientData> for TestContext {
    fn lookup_pair<'a>(
        &'a self,
        key: &'a RecipientId,
    ) -> Option<(&'a MinimalRecipientData, &'a FullRecipientData)> {
        let recipient = match *key {
            Self::CONTACT_ID => &CONTACT_RECIPIENT,
            Self::SELF_ID => &SELF_RECIPIENT,
            Self::PNI_ONLY_ID => &PNI_ONLY_RECIPIENT,
            Self::E164_ONLY_ID => &E164_ONLY_RECIPIENT,
            Self::GROUP_ID => &GROUP_RECIPIENT,
            Self::CALL_LINK_ID => &CALL_LINK_RECIPIENT,
            Self::RELEASE_NOTES_ID => &RELEASE_NOTES_RECIPIENT,
            _ => return None,
        };
        Some((recipient.as_ref(), recipient))
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

impl ReportUnusualTimestamp for TestContext {
    fn report(&self, _since_epoch: u64, _context: &'static str, _issue: TimestampIssue) {
        // Do nothing when not specifically testing timestamps.
    }
}

static TEST_CUSTOM_COLOR: LazyLock<Arc<CustomChatColor>> =
    LazyLock::new(|| Arc::new(CustomChatColor::from_proto_test_data()));

impl TestContext {
    pub(super) const DUPLICATE_PINNED_ORDER: PinOrder = PinOrder(183324u32);
    pub(super) const CUSTOM_CHAT_COLOR_ID: CustomColorId = CustomColorId(555);

    pub(super) fn test_recipient() -> &'static FullRecipientData {
        &SELF_RECIPIENT
    }

    pub(super) fn contact_recipient() -> &'static FullRecipientData {
        &CONTACT_RECIPIENT
    }
}

pub(super) const TEST_MESSAGE_TEXT: &str = "test message text";
