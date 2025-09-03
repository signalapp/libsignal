//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde_with::hex::Hex;
use serde_with::serde_as;
use uuid::Uuid;

use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::backup::{TryIntoWith, serialize};
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
#[cfg_attr(test, derive(PartialEq))]
pub struct LocatorInfo {
    #[serde(with = "hex")]
    key: Vec<u8>,
    integrity_check: IntegrityCheck,
    plaintext_size: u32,
    transit: Option<TransitTierLocator>,
    media_tier_cdn_number: Option<u32>,

    #[serde_as(as = "Option<Hex>")]
    local_key: Option<Vec<u8>>,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum IntegrityCheck {
    EncryptedDigest {
        #[serde(with = "hex")]
        digest: Vec<u8>,
    },
    PlaintextHash {
        #[serde(with = "hex")]
        plaintext_hash: Vec<u8>,
    },
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
    /// Missing integrity check (digest or plaintextHash)
    MissingIntegrityCheck,
    /// localKey is present but plaintextHash is not set
    UnexpectedLocalKey,
    /// Locator had exactly one of transitCdnKey and transitCdnNumber
    TransitCdnMismatch,
    /// Locator had transitCdnUploadTimestamp but not transitCdnKey
    UnexpectedTransitCdnUploadTimestamp,
    /// transitCdnKey was present but empty
    MissingTransitCdnKey,
    /// mediaTierCdnNumber is present but plaintextHash is not set
    UnexpectedMediaTierCdnNumber,
    /// key is present but neither transitCdnKey nor plaintextHash are set
    UnexpectedKey,
    /// encryptedDigest requires transitCdnKey, transitCdnNumber, and key
    EncryptedDigestMissingTransitInfo,
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
            size: plaintext_size,
            integrityCheck,
            transitCdnKey,
            transitCdnNumber,
            transitTierUploadTimestamp,
            mediaTierCdnNumber,
            localKey,
            special_fields: _,
        } = self;

        let transit =
            (transitCdnKey, transitCdnNumber, transitTierUploadTimestamp).try_into_with(context)?;

        let integrity_check = match integrityCheck {
            Some(proto::file_pointer::locator_info::IntegrityCheck::EncryptedDigest(digest)) => {
                if digest.is_empty() {
                    return Err(LocatorError::MissingIntegrityCheck);
                }

                if transit.is_none() || key.is_empty() {
                    return Err(LocatorError::EncryptedDigestMissingTransitInfo);
                }

                IntegrityCheck::EncryptedDigest { digest }
            }
            Some(proto::file_pointer::locator_info::IntegrityCheck::PlaintextHash(hash)) => {
                if hash.is_empty() {
                    return Err(LocatorError::MissingIntegrityCheck);
                }

                IntegrityCheck::PlaintextHash {
                    plaintext_hash: hash,
                }
            }
            None => return Err(LocatorError::MissingIntegrityCheck),
        };

        let has_content =
            transit.is_some() || matches!(integrity_check, IntegrityCheck::PlaintextHash { .. });
        let has_key = !key.is_empty();
        match (has_content, has_key) {
            (true, false) => return Err(LocatorError::MissingKey),
            (false, true) => return Err(LocatorError::UnexpectedKey),
            (true, true) => {} // Content and key are both present, normal happy case.
            (false, false) => {} // Neither content nor key are present, equivalent to old InvalidAttachmentLocator. This is the case for old InvalidAttachmentLocator.
        }

        // If plaintextHash is not set, we have never downloaded the file, so
        // we cannot have a local key. If we have never downloaded it, we also
        // can never have uploaded it to the media tier, so we should not have
        // a media tier CDN number.
        if !matches!(integrity_check, IntegrityCheck::PlaintextHash { .. }) {
            if localKey.is_some() {
                return Err(LocatorError::UnexpectedLocalKey);
            }
            if mediaTierCdnNumber.is_some() {
                return Err(LocatorError::UnexpectedMediaTierCdnNumber);
            }
        }

        Ok(LocatorInfo {
            key,
            local_key: localKey,
            plaintext_size,
            transit,
            media_tier_cdn_number: mediaTierCdnNumber,
            integrity_check,
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
                key: hex!("1234").into(),
                integrityCheck: None, // Will be set by specific test data methods
                size: 123,
                transitCdnKey: Some("ABCDEFG".into()),
                transitCdnNumber: Some(2),
                transitTierUploadTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                localKey: None,
                mediaTierCdnNumber: None,
                special_fields: Default::default(),
            }
        }

        fn test_data_with_plaintext_hash() -> Self {
            Self {
                integrityCheck: Some(
                    proto::file_pointer::locator_info::IntegrityCheck::PlaintextHash(
                        b"plaintextHash".to_vec(),
                    ),
                ),
                localKey: Some(b"local key".to_vec()),
                mediaTierCdnNumber: Some(87),
                ..Self::test_data()
            }
        }

        fn test_data_with_digest() -> Self {
            Self {
                integrityCheck: Some(
                    proto::file_pointer::locator_info::IntegrityCheck::EncryptedDigest(
                        hex!("abcd").into(),
                    ),
                ),
                ..Self::test_data()
            }
        }
    }

    #[test]
    fn valid_locator_info() {
        assert_eq!(
            proto::file_pointer::LocatorInfo::test_data_with_plaintext_hash()
                .try_into_with(&TestContext::default()),
            Ok(Locator::LocatorInfo(LocatorInfo {
                transit: Some(TransitTierLocator {
                    cdn_key: "ABCDEFG".into(),
                    cdn_number: 2,
                    upload_timestamp: Some(Timestamp::test_value())
                }),
                key: vec![0x12, 0x34],
                integrity_check: IntegrityCheck::PlaintextHash {
                    plaintext_hash: b"plaintextHash".to_vec()
                },
                plaintext_size: 123,
                media_tier_cdn_number: Some(87),
                local_key: Some(b"local key".to_vec())
            }))
        )
    }

    #[test]
    fn valid_locator_info_with_digest() {
        assert_eq!(
            proto::file_pointer::LocatorInfo::test_data_with_digest()
                .try_into_with(&TestContext::default()),
            Ok(Locator::LocatorInfo(LocatorInfo {
                transit: Some(TransitTierLocator {
                    cdn_key: "ABCDEFG".into(),
                    cdn_number: 2,
                    upload_timestamp: Some(Timestamp::test_value())
                }),
                key: vec![0x12, 0x34],
                integrity_check: IntegrityCheck::EncryptedDigest {
                    digest: vec![0xab, 0xcd]
                },
                plaintext_size: 123,
                media_tier_cdn_number: None,
                local_key: None
            }))
        )
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| x.integrityCheck = None => Err(LocatorError::MissingIntegrityCheck); "no integrityCheck")]
    #[test_case(|x| x.mediaTierCdnNumber = None => Ok(()); "no mediaTierCdnNumber")]
    #[test_case(|x| x.key = vec![] => Err(LocatorError::MissingKey); "no key")]
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
        let mut locator = proto::file_pointer::LocatorInfo::test_data_with_plaintext_hash();
        modifier(&mut locator);
        locator
            .try_into_with(&TestContext::default())
            .map(|_: Locator| ())
    }

    #[test_case(|_| {} => Ok(()); "valid with digest")]
    #[test_case(|x| x.integrityCheck = Some(proto::file_pointer::locator_info::IntegrityCheck::EncryptedDigest(vec![])) => Err(LocatorError::MissingIntegrityCheck); "empty digest")]
    #[test_case(|x| x.localKey = Some(b"key".to_vec()) => Err(LocatorError::UnexpectedLocalKey); "localKey means we downloaded it, so we should have plaintextHash instead of digest")]
    #[test_case(|x| x.mediaTierCdnNumber = Some(1) => Err(LocatorError::UnexpectedMediaTierCdnNumber); "mediaTierCdnNumber means we uploaded it to the media tier, so we should have calculated a plaintextHash when we did that")]
    #[test_case(|x| {
        x.transitCdnKey = None;
        x.transitCdnNumber = None;
        x.transitTierUploadTimestamp = None;
    } => Err(LocatorError::EncryptedDigestMissingTransitInfo); "no transit CDN info or plaintextHash, but key is present")]
    #[test_case(|x| {
        x.key = vec![];
        x.transitCdnKey = None;
        x.transitCdnNumber = None;
        x.transitTierUploadTimestamp = None;
    } => Err(LocatorError::EncryptedDigestMissingTransitInfo); "digest-only, no key")]
    #[test_case(|x| {
        x.transitCdnKey = None;
        x.transitCdnNumber = None;
        x.transitTierUploadTimestamp = None;
    } => Err(LocatorError::EncryptedDigestMissingTransitInfo); "encryptedDigest without transit info should fail")]
    #[test_case(|x| {
        x.key = vec![];
    } => Err(LocatorError::EncryptedDigestMissingTransitInfo); "encryptedDigest without key should fail")]
    #[test_case(|x| {
        x.transitCdnKey = None;
    } => Err(LocatorError::TransitCdnMismatch); "encryptedDigest without transitCdnKey should fail")]
    #[test_case(|x| {
        x.transitCdnNumber = None;
    } => Err(LocatorError::TransitCdnMismatch); "encryptedDigest without transitCdnNumber should fail")]
    fn locator_info_with_digest(
        modifier: impl FnOnce(&mut proto::file_pointer::LocatorInfo),
    ) -> Result<(), LocatorError> {
        let mut locator = proto::file_pointer::LocatorInfo::test_data_with_digest();
        modifier(&mut locator);
        locator
            .try_into_with(&TestContext::default())
            .map(|_: Locator| ())
    }

    impl proto::FilePointer {
        pub(crate) fn test_data() -> Self {
            Self {
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
        x.locatorInfo = Some(proto::file_pointer::LocatorInfo::test_data_with_plaintext_hash()).into();
    } => Ok(()); "with locatorInfo")]
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
