//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::GroupMasterKeyBytes;

use crate::backup::recipient::RecipientError;
use crate::backup::serialize;
use crate::proto::backup as proto;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct GroupData {
    pub master_key: GroupMasterKeyBytes,
    pub whitelisted: bool,
    pub hide_story: bool,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub story_send_mode: proto::group::StorySendMode,
    #[serde(serialize_with = "serialize::optional_proto_message_as_bytes")]
    pub snapshot: Option<Box<proto::group::GroupSnapshot>>,
}

impl TryFrom<proto::Group> for GroupData {
    type Error = RecipientError;
    fn try_from(value: proto::Group) -> Result<Self, Self::Error> {
        let proto::Group {
            masterKey,
            whitelisted,
            hideStory,
            storySendMode,
            snapshot,
            special_fields: _,
        } = value;

        let master_key = masterKey
            .try_into()
            .map_err(|_| RecipientError::InvalidMasterKey)?;

        let story_send_mode = match storySendMode.enum_value_or_default() {
            s @ (proto::group::StorySendMode::DEFAULT
            | proto::group::StorySendMode::DISABLED
            | proto::group::StorySendMode::ENABLED) => s,
        };

        // TODO consider additional group snapshot validation.
        let snapshot = snapshot.0;

        Ok(GroupData {
            master_key,
            whitelisted,
            hide_story: hideStory,
            story_send_mode,
            snapshot,
        })
    }
}
