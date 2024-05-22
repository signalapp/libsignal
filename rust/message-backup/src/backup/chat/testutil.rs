//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use nonzero_ext::nonzero;
use protobuf::MessageField;

use crate::backup::frame::RecipientId;
use crate::backup::method::{Contains, Lookup};
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

impl Lookup<PinOrder, RecipientId> for TestContext {
    fn lookup(&self, key: &PinOrder) -> Option<&RecipientId> {
        (*key == Self::DUPLICATE_PINNED_ORDER).then_some(&Self::DUPLICATE_PINNED_ORDER_RECIPIENT)
    }
}

impl AsRef<BackupMeta> for TestContext {
    fn as_ref(&self) -> &BackupMeta {
        &self.0
    }
}

impl TestContext {
    pub(super) const DUPLICATE_PINNED_ORDER: PinOrder = PinOrder(nonzero!(183324u32));
    pub(super) const DUPLICATE_PINNED_ORDER_RECIPIENT: RecipientId = RecipientId(183324);
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
