//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use nonzero_ext::nonzero;
use once_cell::sync::Lazy;
use protobuf::MessageField;

use crate::backup::frame::RecipientId;
use crate::backup::method::{Contains, Lookup};
use crate::backup::recipient::{Destination, FullRecipientData};
use crate::backup::time::Timestamp;
use crate::backup::{BackupMeta, Purpose};
use crate::proto::backup as proto;

use super::PinOrder;

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

impl Contains<RecipientId> for TestContext {
    fn contains(&self, key: &RecipientId) -> bool {
        key == &RecipientId(proto::Recipient::TEST_ID)
    }
}

impl Contains<PinOrder> for TestContext {
    fn contains(&self, key: &PinOrder) -> bool {
        Self::lookup(self, key).is_some()
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

static TEST_RECIPIENT: Lazy<FullRecipientData> =
    Lazy::new(|| FullRecipientData::new(Destination::Self_));

impl TestContext {
    pub(super) const DUPLICATE_PINNED_ORDER: PinOrder = PinOrder(nonzero!(183324u32));
    pub(super) fn test_recipient() -> &'static FullRecipientData {
        &TEST_RECIPIENT
    }
}

pub(super) const TEST_MESSAGE_TEXT: &str = "test message text";

pub(super) trait ProtoHasField<T> {
    fn get_field_mut(&mut self) -> &mut T;
}

pub(super) fn no_reactions(message: &mut impl ProtoHasField<Vec<proto::Reaction>>) {
    message.get_field_mut().clear()
}

pub(super) fn invalid_reaction(message: &mut impl ProtoHasField<Vec<proto::Reaction>>) {
    message.get_field_mut().push(proto::Reaction::default());
}

pub(super) fn no_quote(input: &mut impl ProtoHasField<MessageField<proto::Quote>>) {
    *input.get_field_mut() = None.into();
}

pub(super) fn no_attachments(input: &mut impl ProtoHasField<Vec<proto::MessageAttachment>>) {
    input.get_field_mut().clear();
}

pub(super) fn extra_attachment(input: &mut impl ProtoHasField<Vec<proto::MessageAttachment>>) {
    input
        .get_field_mut()
        .push(proto::MessageAttachment::default());
}
