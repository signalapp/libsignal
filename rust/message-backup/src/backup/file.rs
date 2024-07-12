//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complaints about private fields used to prevent construction
// and recommendation of `#[non_exhaustive]`. The annotation only applies
// outside this crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use uuid::Uuid;

use crate::proto::backup::{self as proto, FilePointer};

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct VoiceMessageAttachment {
    pub client_uuid: Option<Uuid>,
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum VoiceMessageAttachmentError {
    /// wrong flag value
    WrongFlag,
    /// missing file pointer
    NoFilePointer,
    /// FilePointer.locator is a oneof but is empty
    NoLocator,
    /// clientUuid is present but invalid
    InvalidUuid,
}

impl TryFrom<proto::MessageAttachment> for VoiceMessageAttachment {
    type Error = VoiceMessageAttachmentError;

    fn try_from(value: proto::MessageAttachment) -> Result<Self, Self::Error> {
        let proto::MessageAttachment {
            pointer,
            flag,
            clientUuid,
            wasDownloaded: _,
            special_fields: _,
        } = value;

        if flag.enum_value_or_default() != proto::message_attachment::Flag::VOICE_MESSAGE {
            return Err(VoiceMessageAttachmentError::WrongFlag);
        }

        let client_uuid = clientUuid
            .map(Uuid::try_from)
            .transpose()
            .map_err(|_: uuid::Error| VoiceMessageAttachmentError::InvalidUuid)?;

        let FilePointer {
            locator,
            // TODO validate these fields
            contentType: _,
            incrementalMac: _,
            incrementalMacChunkSize: _,
            fileName: _,
            width: _,
            height: _,
            caption: _,
            blurHash: _,
            special_fields: _,
        } = pointer
            .into_option()
            .ok_or(VoiceMessageAttachmentError::NoFilePointer)?;

        let _ = locator.ok_or(VoiceMessageAttachmentError::NoLocator)?;

        Ok(VoiceMessageAttachment {
            client_uuid,
            _limit_construction_to_module: (),
        })
    }
}
