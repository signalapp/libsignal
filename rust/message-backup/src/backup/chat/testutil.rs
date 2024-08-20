//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use nonzero_ext::nonzero;
use once_cell::sync::Lazy;

use crate::backup::chat::chat_style::CustomColorId;
use crate::backup::chat::PinOrder;
use crate::backup::frame::RecipientId;
use crate::backup::method::Lookup;
use crate::backup::recipient::{Destination, FullRecipientData};
use crate::backup::time::Timestamp;
use crate::backup::{BackupMeta, Purpose};
use crate::proto::backup as proto;

use super::chat_style::CustomChatColor;

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

impl Lookup<RecipientId, FullRecipientData> for TestContext {
    fn lookup(&self, key: &RecipientId) -> Option<&FullRecipientData> {
        (key.0 == proto::Recipient::TEST_ID).then_some(&TEST_RECIPIENT)
    }
}

impl Lookup<PinOrder, FullRecipientData> for TestContext {
    fn lookup(&self, key: &PinOrder) -> Option<&FullRecipientData> {
        (*key == Self::DUPLICATE_PINNED_ORDER).then_some(&TEST_RECIPIENT)
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
static TEST_RECIPIENT: Lazy<FullRecipientData> =
    Lazy::new(|| FullRecipientData::new(Destination::Self_));

impl TestContext {
    pub(super) const DUPLICATE_PINNED_ORDER: PinOrder = PinOrder(nonzero!(183324u32));
    pub(super) const CUSTOM_CHAT_COLOR_ID: CustomColorId = CustomColorId(555);

    pub(super) fn test_recipient() -> &'static FullRecipientData {
        &TEST_RECIPIENT
    }
}

pub(super) const TEST_MESSAGE_TEXT: &str = "test message text";
