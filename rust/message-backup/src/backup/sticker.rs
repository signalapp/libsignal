//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use derive_where::derive_where;

use crate::backup::file::{FilePointer, FilePointerError};
use crate::backup::method::Method;
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{TryFromWith, TryIntoWith};
use crate::proto::backup as proto;

/// Validated version of [`proto::StickerPack`].
#[derive_where(Debug)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq;
        M::Value<Key>: PartialEq,
    ))]
pub struct StickerPack<M: Method> {
    pub key: M::Value<Key>,
    _limit_construction_to_module: (),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MessageSticker {
    pub pack_id: PackId,
    pub pack_key: Key,
    pub sticker_id: u32,
    pub emoji: Option<String>,
    pub data: FilePointer,
    _limit_construction_to_module: (),
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, serde::Serialize)]
pub struct PackId(#[serde(with = "hex")] [u8; 16]);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
pub struct Key(#[serde(with = "hex")] [u8; 32]);

impl<'a> TryFrom<&'a [u8]> for PackId {
    type Error = <&'a [u8] as TryInto<[u8; 16]>>::Error;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Self)
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = <Vec<u8> as TryInto<[u8; 32]>>::Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.try_into().map(Self)
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum StickerPackError {
    /// key is invalid
    InvalidKey,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum MessageStickerError {
    /// pack ID is invalid
    InvalidPackId,
    /// pack key is invalid
    InvalidPackKey,
    /// missing data pointer
    MissingDataPointer,
    /// data pointer: {0}
    DataPointer(#[from] FilePointerError),
}

impl<M: Method> TryFrom<proto::StickerPack> for StickerPack<M> {
    type Error = StickerPackError;
    fn try_from(value: proto::StickerPack) -> Result<Self, Self::Error> {
        let proto::StickerPack {
            packId: _,
            packKey,
            special_fields: _,
        } = value;

        let key = packKey
            .try_into()
            .map_err(|_| StickerPackError::InvalidKey)?;

        Ok(Self {
            key: M::value(key),
            _limit_construction_to_module: (),
        })
    }
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::Sticker, C> for MessageSticker {
    type Error = MessageStickerError;

    fn try_from_with(item: proto::Sticker, context: &C) -> Result<Self, Self::Error> {
        let proto::Sticker {
            packId,
            packKey,
            stickerId,
            emoji,
            data,
            special_fields: _,
        } = item;

        let pack_id = packId
            .as_slice()
            .try_into()
            .map_err(|_| MessageStickerError::InvalidPackId)?;

        let pack_key = packKey
            .try_into()
            .map_err(|_| MessageStickerError::InvalidPackKey)?;

        let data = data
            .into_option()
            .ok_or(MessageStickerError::MissingDataPointer)?
            .try_into_with(context)?;

        Ok(Self {
            pack_id,
            pack_key,
            sticker_id: stickerId,
            emoji,
            data,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::method::Store;
    use crate::backup::testutil::TestContext;

    impl proto::StickerPack {
        pub(crate) const TEST_ID: PackId = PackId(Self::TEST_ID_BYTES);

        const TEST_ID_BYTES: [u8; 16] = [0x22; 16];
        const TEST_KEY: [u8; 32] = [0x11; 32];

        fn test_data() -> Self {
            Self {
                packId: Self::TEST_ID_BYTES.into(),
                packKey: Self::TEST_KEY.into(),
                ..Default::default()
            }
        }
    }

    impl proto::Sticker {
        pub(crate) const TEST_ID: u32 = 9988;

        pub(crate) fn test_data() -> Self {
            Self {
                packId: proto::StickerPack::TEST_ID_BYTES.into(),
                packKey: proto::StickerPack::TEST_KEY.into(),
                stickerId: Self::TEST_ID,
                data: Some(proto::FilePointer::minimal_test_data()).into(),
                ..Default::default()
            }
        }
    }

    #[test]
    fn valid_sticker_pack() {
        assert_eq!(
            proto::StickerPack::test_data().try_into(),
            Ok(StickerPack::<Store> {
                key: Key(proto::StickerPack::TEST_KEY),
                _limit_construction_to_module: ()
            })
        )
    }

    #[test_case(|x| x.packKey = vec![0xaa; 45] => Err(StickerPackError::InvalidKey); "invalid key")]
    #[test_case(|x| x.packKey = vec![] => Err(StickerPackError::InvalidKey); "no key")]
    fn sticker_pack(mutator: fn(&mut proto::StickerPack)) -> Result<(), StickerPackError> {
        let mut sticker_pack = proto::StickerPack::test_data();
        mutator(&mut sticker_pack);

        sticker_pack.try_into().map(|_: StickerPack<Store>| ())
    }

    #[test]
    fn valid_message_sticker() {
        assert_eq!(
            proto::Sticker::test_data().try_into_with(&TestContext::default()),
            Ok(MessageSticker {
                pack_id: proto::StickerPack::TEST_ID,
                pack_key: Key(proto::StickerPack::TEST_KEY),
                sticker_id: proto::Sticker::TEST_ID,
                emoji: None,
                data: FilePointer::default(),
                _limit_construction_to_module: (),
            })
        );
    }

    #[test_case(|x| x.packKey = vec![0xaa; 45] => Err(MessageStickerError::InvalidPackKey); "invalid key")]
    #[test_case(|x| x.packKey = vec![] => Err(MessageStickerError::InvalidPackKey); "no key")]
    #[test_case(|x| x.packId = vec![123; 3] => Err(MessageStickerError::InvalidPackId); "invalid pack ID")]
    #[test_case(|x| x.stickerId = 555555 => Ok(()); "unknown sticker ID")]
    #[test_case(|x| x.packId = vec![0xff; 16] => Ok(()); "unknown pack ID")]
    #[test_case(|x| x.data = None.into() => Err(MessageStickerError::MissingDataPointer); "no data")]
    #[test_case(
        |x| x.data = Some(proto::FilePointer::default()).into() =>
        Err(MessageStickerError::DataPointer(FilePointerError::NoLocator));
        "invalid data"
    )]
    fn message_sticker(mutator: fn(&mut proto::Sticker)) -> Result<(), MessageStickerError> {
        let mut sticker = proto::Sticker::test_data();
        mutator(&mut sticker);

        sticker
            .try_into_with(&TestContext::default())
            .map(|_: MessageSticker| ())
    }
}
