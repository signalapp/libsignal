//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complaints about private fields used to prevent construction
// and recommendation of `#[non_exhaustive]`. The annotation only applies
// outside this crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use hex::ToHex as _;
use serde_with::hex::Hex;
use serde_with::serde_as;
use uuid::Uuid;

use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::backup::{serialize, TryIntoWith};
use crate::proto::backup as proto;

#[serde_as]
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub enum Locator {
    LocatorInfo(LocatorInfo),
    #[cfg_attr(test, default)]
    Invalid,
}

#[serde_as]
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct LocatorInfo {
    #[serde(with = "hex")]
    key: Vec<u8>,
    #[serde(with = "hex")]
    digest: Vec<u8>,
    size: u32,
    transit: Option<TransitTierLocator>,
    media_tier_cdn_number: Option<u32>,
    media_name: String,
    #[serde_as(as = "Option<Hex>")]
    local_key: Option<Vec<u8>>,
}

#[serde_as]
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct TransitTierLocator {
    cdn_key: String,
    cdn_number: u32,
    upload_timestamp: Option<Timestamp>,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum LocatorError {
    /// Missing key
    MissingKey,
    /// Missing digest
    MissingDigest,
    /// Locator had exactly one of transitCdnKey and transitCdnNumber
    TransitCdnMismatch,
    /// Locator had transitCdnUploadTimestamp but not transitCdnKey
    UnexpectedTransitCdnUploadTimestamp,
    /// transitCdnKey was present but empty
    MissingTransitCdnKey,
    /// mediaName isn't digest encoded as hex (maybe with "_thumbnail" suffix)
    InvalidMediaName,
    /// mediaName is empty but mediaTierCdnNumber is present
    UnexpectedMediaTierCdnNumber,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl<C: ReportUnusualTimestamp + ?Sized> TryIntoWith<Locator, C>
    for proto::file_pointer::LocatorInfo
{
    type Error = LocatorError;

    fn try_into_with(self, context: &C) -> Result<Locator, Self::Error> {
        // The "invalid" locator is encoded as an empty message.
        if self == proto::file_pointer::LocatorInfo::default() {
            return Ok(Locator::Invalid);
        }

        self.try_into_with(context).map(Locator::LocatorInfo)
    }
}

impl<C: ReportUnusualTimestamp + ?Sized> TryIntoWith<LocatorInfo, C>
    for proto::file_pointer::LocatorInfo
{
    type Error = LocatorError;

    fn try_into_with(self, context: &C) -> Result<LocatorInfo, Self::Error> {
        let proto::file_pointer::LocatorInfo {
            key,
            digest,
            size,
            transitCdnKey,
            transitCdnNumber,
            transitTierUploadTimestamp,
            mediaTierCdnNumber,
            mediaName,
            localKey,
            special_fields: _,
        } = self;

        if key.is_empty() {
            return Err(LocatorError::MissingKey);
        }
        if digest.is_empty() {
            return Err(LocatorError::MissingDigest);
        }

        let media_name = if mediaName.is_empty() {
            if mediaTierCdnNumber.is_some() {
                return Err(LocatorError::UnexpectedMediaTierCdnNumber);
            }
            mediaName
        } else {
            let media_name = mediaName.strip_suffix("_thumbnail").unwrap_or(&mediaName);
            if !media_name.eq_ignore_ascii_case(&digest.encode_hex::<String>()) {
                return Err(LocatorError::InvalidMediaName);
            }
            mediaName
        };

        let transit =
            (transitCdnKey, transitCdnNumber, transitTierUploadTimestamp).try_into_with(context)?;

        Ok(LocatorInfo {
            key,
            local_key: localKey,
            digest,
            size,
            transit,
            media_tier_cdn_number: mediaTierCdnNumber,
            media_name,
        })
    }
}

impl<C: ReportUnusualTimestamp + ?Sized> TryIntoWith<Option<TransitTierLocator>, C>
    for (Option<String>, Option<u32>, Option<u64>)
{
    type Error = LocatorError;

    fn try_into_with(self, context: &C) -> Result<Option<TransitTierLocator>, Self::Error> {
        let (transit_cdn_key, transit_cdn_number, transit_tier_upload_timestamp) = self;
        match (
            transit_cdn_key,
            transit_cdn_number,
            transit_tier_upload_timestamp,
        ) {
            (None, Some(_), _) | (Some(_), None, _) => Err(LocatorError::TransitCdnMismatch),
            (None, None, Some(_)) => Err(LocatorError::UnexpectedTransitCdnUploadTimestamp),
            (None, None, None) => Ok(None),
            (Some(cdn_key), Some(cdn_number), upload_timestamp) => {
                if cdn_key.is_empty() {
                    return Err(LocatorError::MissingTransitCdnKey);
                }

                let upload_timestamp = upload_timestamp
                    .map(|t| {
                        Timestamp::from_millis(
                            t,
                            "LocatorInfo.transitTierUploadTimestamp",
                            &context,
                        )
                    })
                    .transpose()?;
                Ok(Some(TransitTierLocator {
                    cdn_key,
                    cdn_number,
                    upload_timestamp,
                }))
            }
        }
    }
}

#[serde_as]
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct FilePointer {
    pub locator_info: Locator,
    pub content_type: Option<String>,
    #[serde_as(as = "Option<Hex>")]
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
    /// FilePointer.locatorInfo is missing
    NoLocatorInfo,
    /// Locator info: {0}
    Locator(#[from] LocatorError),
    /// incrementalMac was present but empty
    MissingIncrementalMac,
    /// Found exactly one of incrementalMac and incrementalMacChunkSize
    IncrementalMacMismatch,
}

impl<C: ReportUnusualTimestamp + ?Sized> TryIntoWith<FilePointer, C> for proto::FilePointer {
    type Error = FilePointerError;

    fn try_into_with(self, context: &C) -> Result<FilePointer, Self::Error> {
        let proto::FilePointer {
            locator: legacy_locator,
            contentType,
            incrementalMac,
            incrementalMacChunkSize,
            fileName,
            width,
            height,
            caption,
            blurHash,
            locatorInfo,
            special_fields: _,
        } = self;

        // The legacy locator format is deprecated and will soon no longer be
        // accepted. Just ignore it for now.
        drop(legacy_locator);

        let locator_info = locatorInfo
            .into_option()
            .ok_or(FilePointerError::NoLocatorInfo)?
            .try_into_with(context)?;

        if incrementalMac.is_some() != incrementalMacChunkSize.is_some() {
            return Err(FilePointerError::IncrementalMacMismatch);
        }

        if incrementalMac.as_deref() == Some(&[]) {
            return Err(FilePointerError::MissingIncrementalMac);
        }

        Ok(FilePointer {
            locator_info,
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

#[serde_as]
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(Default, PartialEq))]
pub struct MessageAttachment {
    pub pointer: FilePointer,
    #[serde_as(as = "serialize::EnumAsString")]
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

impl<C: ReportUnusualTimestamp + ?Sized> TryIntoWith<MessageAttachment, C>
    for proto::MessageAttachment
{
    type Error = MessageAttachmentError;

    fn try_into_with(self, context: &C) -> Result<MessageAttachment, Self::Error> {
        let proto::MessageAttachment {
            pointer,
            flag,
            clientUuid,
            wasDownloaded: _,
            special_fields: _,
        } = self;

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
    use const_str::hex;
    use test_case::test_case;

    use super::*;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    impl proto::file_pointer::LocatorInfo {
        fn test_data() -> Self {
            Self {
                mediaName: "5678".into(),
                key: hex!("1234").into(),
                digest: hex!("5678").into(),
                size: 123,
                transitCdnKey: Some("ABCDEFG".into()),
                transitCdnNumber: Some(2),
                transitTierUploadTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                localKey: Some(b"local key".to_vec()),
                mediaTierCdnNumber: Some(87),
                special_fields: Default::default(),
            }
        }
    }

    #[test]
    fn valid_locator_info() {
        assert_eq!(
            proto::file_pointer::LocatorInfo::test_data().try_into_with(&TestContext::default()),
            Ok(Locator::LocatorInfo(LocatorInfo {
                transit: Some(TransitTierLocator {
                    cdn_key: "ABCDEFG".into(),
                    cdn_number: 2,
                    upload_timestamp: Some(Timestamp::test_value())
                }),
                key: vec![0x12, 0x34],
                digest: vec![0x56, 0x78],
                size: 123,
                media_tier_cdn_number: Some(87),
                media_name: "5678".into(),
                local_key: Some(b"local key".to_vec())
            }))
        )
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| {x.mediaName = "".into(); x.mediaTierCdnNumber = None } => Ok(()); "mediaName can be empty")]
    #[test_case(|x| x.mediaName = "1234".into() => Err(LocatorError::InvalidMediaName); "invalid mediaName")]
    #[test_case(|x| x.mediaName = "5678_thumbnail".into() => Ok(()); "thumbnail mediaName")]
    #[test_case(|x| x.mediaName = "".into() => Err(LocatorError::UnexpectedMediaTierCdnNumber); "mediaTierCdnNumber without mediaName")]
    #[test_case(|x| x.mediaTierCdnNumber = None => Ok(()); "no mediaTierCdnNumber")]
    #[test_case(|x| x.key = vec![] => Err(LocatorError::MissingKey); "no key")]
    #[test_case(|x| x.digest = vec![] => Err(LocatorError::MissingDigest); "no digest")]
    #[test_case(|x| x.size = 0 => Ok(()); "size zero")]
    #[test_case(|x| x.transitCdnKey = None => Err(LocatorError::TransitCdnMismatch); "no transitCdnKey")]
    #[test_case(|x| x.transitCdnKey = Some("".into()) => Err(LocatorError::MissingTransitCdnKey); "empty transitCdnKey")]
    #[test_case(|x| x.transitCdnNumber = None => Err(LocatorError::TransitCdnMismatch); "no transitCdnNumber")]
    #[test_case(|x| {
        x.transitCdnKey = None;
        x.transitCdnNumber = None
     } => Err(LocatorError::UnexpectedTransitCdnUploadTimestamp); "transitTierUploadTimestamp without CDN info")]
    #[test_case(|x| x.transitTierUploadTimestamp = None => Ok(()); "no transitTierUploadTimestamp")]
    #[test_case(|x| x.transitTierUploadTimestamp = Some(100_000_000_000_000_000) => matches Err(LocatorError::InvalidTimestamp(_)); "invalid transitTierUploadTimestamp")]
    #[test_case(|x| {
        x.transitCdnKey = None;
        x.transitCdnNumber = None;
        x.transitTierUploadTimestamp = None;
    } => Ok(()); "no transitCdn/Tier fields")]
    fn locator_info(
        modifier: impl FnOnce(&mut proto::file_pointer::LocatorInfo),
    ) -> Result<(), LocatorError> {
        let mut locator = proto::file_pointer::LocatorInfo::test_data();
        modifier(&mut locator);
        locator
            .try_into_with(&TestContext::default())
            .map(|_: Locator| ())
    }

    impl proto::FilePointer {
        pub(crate) fn test_data() -> Self {
            Self {
                locator: Some(proto::file_pointer::Locator::InvalidAttachmentLocator(
                    proto::file_pointer::InvalidAttachmentLocator::default(),
                )),
                locatorInfo: Some(proto::file_pointer::LocatorInfo::default()).into(),
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
                locatorInfo: Some(proto::file_pointer::LocatorInfo::default()).into(),
                ..Self::default()
            }
        }
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| {
        x.locatorInfo = Some(proto::file_pointer::LocatorInfo::test_data()).into();
    } => Ok(()); "with locatorInfo")]
    #[test_case(|x| x.locator = None => Ok(()); "no legacy locator")]
    #[test_case(|x| x.locatorInfo = None.into() => Err(FilePointerError::NoLocatorInfo); "no locatorInfo")]
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
        pointer.try_into_with(&TestContext::default()).map(|_| ())
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
