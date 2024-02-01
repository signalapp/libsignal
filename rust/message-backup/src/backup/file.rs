//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::backup::{self as proto, FilePointer};

#[derive(Debug)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct VoiceMessageAttachment {
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum VoiceMessageAttachmentError {
    /// wrong flag value
    WrongFlag,
    /// missing file pointer
    NoFilePointer,
}

impl TryFrom<proto::MessageAttachment> for VoiceMessageAttachment {
    type Error = VoiceMessageAttachmentError;

    fn try_from(value: proto::MessageAttachment) -> Result<Self, Self::Error> {
        let proto::MessageAttachment {
            pointer,
            flag,
            special_fields: _,
        } = value;

        if flag.enum_value_or_default() != proto::message_attachment::Flag::VOICE_MESSAGE {
            return Err(VoiceMessageAttachmentError::WrongFlag);
        }

        let FilePointer {
            // TODO validate these fields
            key: _,
            contentType: _,
            size: _,
            incrementalMac: _,
            incrementalMacChunkSize: _,
            fileName: _,
            width: _,
            height: _,
            caption: _,
            blurHash: _,
            locator: _,
            special_fields: _,
        } = pointer
            .into_option()
            .ok_or(VoiceMessageAttachmentError::NoFilePointer)?;

        Ok(VoiceMessageAttachment {
            _limit_construction_to_module: (),
        })
    }
}
