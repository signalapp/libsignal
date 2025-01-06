//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complaints about private fields used to prevent construction
// and recommendation of `#[non_exhaustive]`. The annotation only applies
// outside this crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use hex::ToHex as _;
use uuid::Uuid;

use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::backup::{serialize, TryFromWith, TryIntoWith};
use crate::proto::backup as proto;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub enum AttachmentLocator {
    Backup {
        cdn_number: Option<u32>,
        #[serde(with = "hex")]
        key: Vec<u8>,
        #[serde(with = "hex")]
        digest: Vec<u8>,
        is_thumbnail: bool,
        size: u32,
        transit_cdn_key: Option<String>,
        transit_cdn_number: Option<u32>,
    },
    Transit {
        cdn_key: String,
        cdn_number: u32,
        upload_timestamp: Option<Timestamp>,
        #[serde(with = "hex")]
        key: Vec<u8>,
        #[serde(with = "hex")]
        digest: Vec<u8>,
        size: u32,
    },
    #[cfg_attr(test, default)]
    Invalid,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum AttachmentLocatorError {
    /// Missing mediaName
    MissingMediaName,
    /// Missing cdnKey
    MissingCdnKey,
    /// Missing key
    MissingKey,
    /// Missing digest
    MissingDigest,
    /// Backup locator had exactly one of transitCdnKey and transitCdnNumber
    TransitCdnMismatch,
    /// transitCdnKey was present but empty
    MissingTransitCdnKey,
    /// mediaName isn't digest encoded as hex (maybe with "_thumbnail" suffix)
    InvalidMediaName,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl<C: ReportUnusualTimestamp + ?Sized> TryFromWith<proto::file_pointer::Locator, C>
    for AttachmentLocator
{
    type Error = AttachmentLocatorError;

    fn try_from_with(
        value: proto::file_pointer::Locator,
        context: &C,
    ) -> Result<Self, Self::Error> {
        match value {
            proto::file_pointer::Locator::BackupLocator(proto::file_pointer::BackupLocator {
                mediaName,
                cdnNumber,
                key,
                digest,
                size,
                transitCdnKey,
                transitCdnNumber,
                special_fields: _,
            }) => {
                if mediaName.is_empty() {
                    return Err(AttachmentLocatorError::MissingMediaName);
                }
                if key.is_empty() {
                    return Err(AttachmentLocatorError::MissingKey);
                }
                if digest.is_empty() {
                    return Err(AttachmentLocatorError::MissingDigest);
                }
                if transitCdnKey.is_some() != transitCdnNumber.is_some() {
                    return Err(AttachmentLocatorError::TransitCdnMismatch);
                }
                if transitCdnKey.as_deref() == Some("") {
                    return Err(AttachmentLocatorError::MissingTransitCdnKey);
                }

                let (is_thumbnail, media_name) = match mediaName.strip_suffix("_thumbnail") {
                    Some(media_name) => (true, media_name),
                    None => (false, &*mediaName),
                };
                if !media_name.eq_ignore_ascii_case(&digest.encode_hex::<String>()) {
                    return Err(AttachmentLocatorError::InvalidMediaName);
                }

                Ok(Self::Backup {
                    cdn_number: cdnNumber,
                    key,
                    digest,
                    is_thumbnail,
                    size,
                    transit_cdn_key: transitCdnKey,
                    transit_cdn_number: transitCdnNumber,
                })
            }
            proto::file_pointer::Locator::AttachmentLocator(
                proto::file_pointer::AttachmentLocator {
                    cdnKey,
                    cdnNumber,
                    uploadTimestamp,
                    key,
                    digest,
                    size,
                    special_fields: _,
                },
            ) => {
                if cdnKey.is_empty() {
                    return Err(AttachmentLocatorError::MissingCdnKey);
                }
                if key.is_empty() {
                    return Err(AttachmentLocatorError::MissingKey);
                }
                if digest.is_empty() {
                    return Err(AttachmentLocatorError::MissingDigest);
                }

                let upload_timestamp = uploadTimestamp
                    .map(|upload_timestamp| {
                        Timestamp::from_millis(
                            upload_timestamp,
                            "AttachmentLocator.uploadTimestamp",
                            &context,
                        )
                    })
                    .transpose()?;

                Ok(Self::Transit {
                    cdn_key: cdnKey,
                    cdn_number: cdnNumber,
                    upload_timestamp,
                    key,
                    digest,
                    size,
                })
            }
            proto::file_pointer::Locator::InvalidAttachmentLocator(
                proto::file_pointer::InvalidAttachmentLocator { special_fields: _ },
            ) => Ok(Self::Invalid),
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct FilePointer {
    pub locator: AttachmentLocator,
    pub content_type: Option<String>,
    #[serde(serialize_with = "serialize::optional_hex")]
    pub incremental_mac: Option<Vec<u8>>,
    pub incremental_mac_chunk_size: Option<u32>,
    pub file_name: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub caption: Option<String>,
    pub blur_hash: Option<String>,
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum FilePointerError {
    /// FilePointer.locator is a oneof but is empty
    NoLocator,
    /// Locator: {0}
    Locator(#[from] AttachmentLocatorError),
    /// incrementalMac was present but empty
    MissingIncrementalMac,
    /// Found exactly one of incrementalMac and incrementalMacChunkSize
    IncrementalMacMismatch,
}

impl<C: ReportUnusualTimestamp + ?Sized> TryFromWith<proto::FilePointer, C> for FilePointer {
    type Error = FilePointerError;

    fn try_from_with(value: proto::FilePointer, context: &C) -> Result<Self, Self::Error> {
        let proto::FilePointer {
            locator,
            contentType,
            incrementalMac,
            incrementalMacChunkSize,
            fileName,
            width,
            height,
            caption,
            blurHash,
            special_fields: _,
        } = value;

        let locator = locator
            .ok_or(FilePointerError::NoLocator)?
            .try_into_with(context)?;

        if incrementalMac.is_some() != incrementalMacChunkSize.is_some() {
            return Err(FilePointerError::IncrementalMacMismatch);
        }

        if incrementalMac.as_deref() == Some(&[]) {
            return Err(FilePointerError::MissingIncrementalMac);
        }

        Ok(Self {
            locator,
            content_type: contentType,
            incremental_mac: incrementalMac,
            incremental_mac_chunk_size: incrementalMacChunkSize,
            file_name: fileName,
            width,
            height,
            caption,
            blur_hash: blurHash,
            _limit_construction_to_module: (),
        })
    }
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct MessageAttachment {
    pub pointer: FilePointer,
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub flag: proto::message_attachment::Flag,
    pub client_uuid: Option<Uuid>,
    #[serde(skip)]
    _limit_construction_to_module: (),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum MessageAttachmentError {
    /// missing file pointer
    NoFilePointer,
    /// file pointer: {0}
    FilePointer(#[from] FilePointerError),
    /// clientUuid is present but invalid
    InvalidUuid,
}

impl<C: ReportUnusualTimestamp + ?Sized> TryFromWith<proto::MessageAttachment, C>
    for MessageAttachment
{
    type Error = MessageAttachmentError;

    fn try_from_with(value: proto::MessageAttachment, context: &C) -> Result<Self, Self::Error> {
        let proto::MessageAttachment {
            pointer,
            flag,
            clientUuid,
            wasDownloaded: _,
            special_fields: _,
        } = value;

        let client_uuid = clientUuid
            .map(Uuid::try_from)
            .transpose()
            .map_err(|_: uuid::Error| MessageAttachmentError::InvalidUuid)?;

        let pointer = pointer
            .into_option()
            .ok_or(MessageAttachmentError::NoFilePointer)?
            .try_into_with(context)?;

        Ok(MessageAttachment {
            pointer,
            flag: flag.enum_value_or_default(),
            client_uuid,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use test_case::test_case;

    use super::*;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    impl proto::file_pointer::BackupLocator {
        fn test_data() -> Self {
            Self {
                mediaName: "5678".into(),
                cdnNumber: Some(3),
                key: hex!("1234").into(),
                digest: hex!("5678").into(),
                size: 123,
                transitCdnKey: Some("ABCDEFG".into()),
                transitCdnNumber: Some(2),
                special_fields: Default::default(),
            }
        }
    }

    #[test]
    fn valid_backup_locator() {
        assert_eq!(
            proto::file_pointer::Locator::BackupLocator(
                proto::file_pointer::BackupLocator::test_data()
            )
            .try_into_with(&TestContext::default()),
            Ok(AttachmentLocator::Backup {
                cdn_number: Some(3),
                key: vec![0x12, 0x34],
                digest: vec![0x56, 0x78],
                is_thumbnail: false,
                size: 123,
                transit_cdn_key: Some("ABCDEFG".into()),
                transit_cdn_number: Some(2),
            })
        )
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| x.mediaName = "".into() => Err(AttachmentLocatorError::MissingMediaName); "no mediaName")]
    #[test_case(|x| x.mediaName = "1234".into() => Err(AttachmentLocatorError::InvalidMediaName); "invalid mediaName")]
    #[test_case(|x| x.mediaName = "5678_thumbnail".into() => Ok(()); "thumbnail mediaName")]
    #[test_case(|x| x.cdnNumber = None => Ok(()); "no cdnNumber")]
    #[test_case(|x| x.key = vec![] => Err(AttachmentLocatorError::MissingKey); "no key")]
    #[test_case(|x| x.digest = vec![] => Err(AttachmentLocatorError::MissingDigest); "no digest")]
    #[test_case(|x| x.size = 0 => Ok(()); "size zero")]
    #[test_case(|x| x.transitCdnKey = None => Err(AttachmentLocatorError::TransitCdnMismatch); "no transitCdnKey")]
    #[test_case(|x| x.transitCdnKey = Some("".into()) => Err(AttachmentLocatorError::MissingTransitCdnKey); "empty transitCdnKey")]
    #[test_case(|x| x.transitCdnNumber = None => Err(AttachmentLocatorError::TransitCdnMismatch); "no transitCdnNumber")]
    #[test_case(|x| {
        x.transitCdnKey = None;
        x.transitCdnNumber = None;
    } => Ok(()); "no transitCdn fields")]
    fn backup_locator(
        modifier: impl FnOnce(&mut proto::file_pointer::BackupLocator),
    ) -> Result<(), AttachmentLocatorError> {
        let mut locator = proto::file_pointer::BackupLocator::test_data();
        modifier(&mut locator);
        AttachmentLocator::try_from_with(
            proto::file_pointer::Locator::BackupLocator(locator),
            &TestContext::default(),
        )
        .map(|_| ())
    }

    impl proto::file_pointer::AttachmentLocator {
        fn test_data() -> Self {
            Self {
                cdnKey: "ABCDEFG".into(),
                cdnNumber: 3,
                uploadTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                key: hex!("1234").into(),
                digest: hex!("5678").into(),
                size: 123,
                special_fields: Default::default(),
            }
        }
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| x.cdnKey = "".into() => Err(AttachmentLocatorError::MissingCdnKey); "no cdnKey")]
    #[test_case(|x| x.key = vec![] => Err(AttachmentLocatorError::MissingKey); "no key")]
    #[test_case(|x| x.digest = vec![] => Err(AttachmentLocatorError::MissingDigest); "no digest")]
    #[test_case(|x| x.size = 0 => Ok(()); "size zero")]
    #[test_case(
        |x| x.uploadTimestamp = Some(MillisecondsSinceEpoch::FAR_FUTURE.0) =>
        Err(AttachmentLocatorError::InvalidTimestamp(TimestampError("AttachmentLocator.uploadTimestamp", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid timestamp"
    )]
    fn attachment_locator(
        modifier: impl FnOnce(&mut proto::file_pointer::AttachmentLocator),
    ) -> Result<(), AttachmentLocatorError> {
        let mut locator = proto::file_pointer::AttachmentLocator::test_data();
        modifier(&mut locator);
        AttachmentLocator::try_from_with(
            proto::file_pointer::Locator::AttachmentLocator(locator),
            &TestContext::default(),
        )
        .map(|_| ())
    }

    impl proto::FilePointer {
        pub(crate) fn test_data() -> Self {
            Self {
                locator: Some(proto::file_pointer::Locator::InvalidAttachmentLocator(
                    proto::file_pointer::InvalidAttachmentLocator::default(),
                )),
                contentType: Some("image/jpeg".into()),
                incrementalMac: Some(hex!("1234").into()),
                incrementalMacChunkSize: Some(16),
                fileName: Some("test.jpg".into()),
                width: Some(640),
                height: Some(480),
                caption: Some("test caption".into()),
                blurHash: Some("abcd".into()),
                special_fields: Default::default(),
            }
        }

        pub(crate) fn minimal_test_data() -> Self {
            Self {
                locator: Some(proto::file_pointer::Locator::InvalidAttachmentLocator(
                    proto::file_pointer::InvalidAttachmentLocator::default(),
                )),
                ..Self::default()
            }
        }
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| {
        x.locator = Some(proto::file_pointer::Locator::BackupLocator(
            proto::file_pointer::BackupLocator::test_data()
        ));
    } => Ok(()); "with BackupLocator")]
    #[test_case(|x| {
        x.locator = Some(proto::file_pointer::Locator::AttachmentLocator(
            proto::file_pointer::AttachmentLocator::test_data()
        ));
    } => Ok(()); "with AttachmentLocator")]
    #[test_case(|x| x.locator = None => Err(FilePointerError::NoLocator); "no locator")]
    #[test_case(|x| x.contentType = None => Ok(()); "no contentType")]
    #[test_case(|x| x.contentType = Some("".into()) => Ok(()); "empty contentType")]
    #[test_case(|x| x.incrementalMac = None => Err(FilePointerError::IncrementalMacMismatch); "no incrementalMac")]
    #[test_case(|x| x.incrementalMac = Some("".into()) => Err(FilePointerError::MissingIncrementalMac); "empty incrementalMac")]
    #[test_case(|x| x.incrementalMacChunkSize = None => Err(FilePointerError::IncrementalMacMismatch); "no incrementalMacChunkSize")]
    #[test_case(|x| {
        x.incrementalMac = None;
        x.incrementalMacChunkSize = None;
    } => Ok(()); "no incrementalMac fields")]
    #[test_case(|x| x.fileName = None => Ok(()); "no fileName")]
    #[test_case(|x| x.fileName = Some("".into()) => Ok(()); "empty fileName")]
    #[test_case(|x| x.width = None => Ok(()); "no width")]
    #[test_case(|x| x.width = Some(0) => Ok(()); "zero width")]
    #[test_case(|x| x.height = None => Ok(()); "no height")]
    #[test_case(|x| x.height = Some(0) => Ok(()); "zero height")]
    #[test_case(|x| x.caption = None => Ok(()); "no caption")]
    #[test_case(|x| x.caption = Some("".into()) => Ok(()); "empty caption")]
    #[test_case(|x| x.blurHash = None => Ok(()); "no blurHash")]
    #[test_case(|x| x.blurHash = Some("".into()) => Ok(()); "empty blurHash")]
    fn file_pointer(
        modifier: impl FnOnce(&mut proto::FilePointer),
    ) -> Result<(), FilePointerError> {
        let mut pointer = proto::FilePointer::test_data();
        modifier(&mut pointer);
        FilePointer::try_from_with(pointer, &TestContext::default()).map(|_| ())
    }

    impl proto::MessageAttachment {
        const TEST_UUID: [u8; 16] = [0xAA; 16];

        pub(crate) fn test_data() -> Self {
            Self {
                pointer: Some(proto::FilePointer::minimal_test_data()).into(),
                clientUuid: Some(Self::TEST_UUID.into()),
                ..Self::default()
            }
        }

        pub(crate) fn test_voice_message_data() -> Self {
            Self {
                flag: proto::message_attachment::Flag::VOICE_MESSAGE.into(),
                ..Self::test_data()
            }
        }
    }

    impl MessageAttachment {
        pub(crate) fn from_proto_test_data() -> Self {
            Self {
                pointer: FilePointer::default(),
                client_uuid: Some(uuid::Uuid::from_bytes(proto::MessageAttachment::TEST_UUID)),
                flag: Default::default(),
                _limit_construction_to_module: (),
            }
        }

        pub(crate) fn from_proto_voice_message_data() -> Self {
            Self {
                flag: proto::message_attachment::Flag::VOICE_MESSAGE,
                ..Self::from_proto_test_data()
            }
        }
    }
}
