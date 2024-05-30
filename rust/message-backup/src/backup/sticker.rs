//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use derive_where::derive_where;

use crate::backup::method::{KeyExists, Map as _, Method};
use crate::backup::WithId;
use crate::proto::backup as proto;

/// Validated version of [`proto::StickerPack`].
#[derive_where(Debug)]
#[cfg_attr(test, derive_where(PartialEq;
        M::Map<StickerId, PackSticker>: PartialEq,
        M::Value<Key>: PartialEq,
        M::Value<String>: PartialEq
    ))]
pub struct StickerPack<M: Method> {
    pub key: M::Value<Key>,
    pub stickers: M::Map<StickerId, PackSticker>,
    pub title: M::Value<String>,
    pub author: M::Value<String>,
    _limit_construction_to_module: (),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PackSticker {
    pub id: StickerId,
    pub emoji: String,
    _limit_construction_to_module: (),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MessageSticker {
    pub pack_id: PackId,
    pub pack_key: Key,
    pub emoji: Option<String>,
    _limit_construction_to_module: (),
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PackId([u8; 16]);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Key([u8; 32]);

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

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct StickerId(u32);

impl WithId for proto::StickerPackSticker {
    type Id = StickerId;
    fn id(&self) -> Self::Id {
        StickerId(self.id)
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum StickerPackError {
    /// key is invalid
    InvalidKey,
    /// sticker pack ID is invalid
    InvalidPackId,
    /// {0:?} contains more than one sticker with {0:?}
    DuplicateId(PackId, StickerId),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum MessageStickerError {
    /// pack ID is invalid
    InvalidPackId,
    /// pack key is invalid
    InvalidPackKey,
}

impl<M: Method> TryFrom<proto::StickerPack> for StickerPack<M> {
    type Error = StickerPackError;
    fn try_from(value: proto::StickerPack) -> Result<Self, Self::Error> {
        let proto::StickerPack {
            packId,
            packKey,
            stickers,
            title,
            author,
            special_fields: _,
        } = value;

        let pack_id = PackId(
            packId
                .try_into()
                .map_err(|_| StickerPackError::InvalidPackId)?,
        );

        let key = packKey
            .try_into()
            .map_err(|_| StickerPackError::InvalidKey)?;

        let stickers = {
            let mut out = M::Map::default();
            for sticker in stickers {
                let sticker: PackSticker = sticker.try_into()?;
                let id = sticker.id;
                out.insert(id, sticker)
                    .map_err(|KeyExists| StickerPackError::DuplicateId(pack_id, id))?;
            }
            out
        };

        Ok(Self {
            key: M::value(key),
            stickers,
            title: M::value(title),
            author: M::value(author),
            _limit_construction_to_module: (),
        })
    }
}

impl TryFrom<proto::StickerPackSticker> for PackSticker {
    type Error = StickerPackError;
    fn try_from(value: proto::StickerPackSticker) -> Result<Self, Self::Error> {
        let proto::StickerPackSticker {
            id,
            emoji,
            special_fields: _,
        } = value;

        Ok(Self {
            id: StickerId(id),
            emoji,
            _limit_construction_to_module: (),
        })
    }
}

impl TryFrom<proto::Sticker> for MessageSticker {
    type Error = MessageStickerError;

    fn try_from(item: proto::Sticker) -> Result<Self, Self::Error> {
        let proto::Sticker {
            packId,
            packKey,
            stickerId: _,
            emoji,
            special_fields: _,
            // TODO validate these fields
            data: _,
        } = item;

        let pack_id = packId
            .as_slice()
            .try_into()
            .map_err(|_| MessageStickerError::InvalidPackId)?;

        let pack_key = packKey
            .try_into()
            .map_err(|_| MessageStickerError::InvalidPackKey)?;

        Ok(Self {
            pack_id,
            pack_key,
            emoji,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use test_case::test_case;

    use crate::backup::method::Store;

    use super::*;

    impl proto::StickerPack {
        pub(crate) const TEST_ID: PackId = PackId(Self::TEST_ID_BYTES);

        const TEST_ID_BYTES: [u8; 16] = [0x22; 16];
        const TEST_KEY: [u8; 32] = [0x11; 32];

        fn test_data() -> Self {
            Self {
                packId: Self::TEST_ID_BYTES.into(),
                packKey: Self::TEST_KEY.into(),
                stickers: vec![proto::StickerPackSticker::test_data()],
                author: "author".to_owned(),
                title: "title".to_owned(),
                ..Default::default()
            }
        }
    }

    impl proto::StickerPackSticker {
        pub(crate) const TEST_ID: StickerId = StickerId(9988);

        fn test_data() -> Self {
            Self {
                id: Self::TEST_ID.0,
                ..Self::default()
            }
        }
    }

    impl proto::Sticker {
        pub(crate) fn test_data() -> Self {
            Self {
                packId: proto::StickerPack::TEST_ID_BYTES.into(),
                packKey: proto::StickerPack::TEST_KEY.into(),
                stickerId: proto::StickerPackSticker::TEST_ID.0,
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
                stickers: HashMap::from([(
                    proto::StickerPackSticker::TEST_ID,
                    PackSticker {
                        id: proto::StickerPackSticker::TEST_ID,
                        emoji: "".to_owned(),
                        _limit_construction_to_module: (),
                    }
                )]),
                title: "title".to_owned(),
                author: "author".to_owned(),
                _limit_construction_to_module: ()
            })
        )
    }

    trait StickerPackFields {
        fn pack_key_mut(&mut self) -> &mut Vec<u8>;
    }
    impl StickerPackFields for proto::StickerPack {
        fn pack_key_mut(&mut self) -> &mut Vec<u8> {
            &mut self.packKey
        }
    }
    impl StickerPackFields for proto::Sticker {
        fn pack_key_mut(&mut self) -> &mut Vec<u8> {
            &mut self.packKey
        }
    }

    fn invalid_key(pack: &mut impl StickerPackFields) {
        *pack.pack_key_mut() = vec![0xaa; 45];
    }
    fn no_key(pack: &mut impl StickerPackFields) {
        *pack.pack_key_mut() = vec![];
    }
    fn no_stickers(pack: &mut proto::StickerPack) {
        pack.stickers = vec![];
    }

    #[test_case(invalid_key, Err(StickerPackError::InvalidKey))]
    #[test_case(no_key, Err(StickerPackError::InvalidKey))]
    #[test_case(no_stickers, Ok(()))]
    fn sticker_pack(mutator: fn(&mut proto::StickerPack), expected: Result<(), StickerPackError>) {
        let mut sticker_pack = proto::StickerPack::test_data();
        mutator(&mut sticker_pack);

        let result = sticker_pack.try_into().map(|_: StickerPack<Store>| ());
        assert_eq!(result, expected);
    }

    #[test]
    fn valid_message_sticker() {
        assert_eq!(
            proto::Sticker::test_data().try_into(),
            Ok(MessageSticker {
                pack_id: proto::StickerPack::TEST_ID,
                pack_key: Key(proto::StickerPack::TEST_KEY),
                emoji: None,
                _limit_construction_to_module: (),
            })
        );
    }

    fn invalid_pack_id(input: &mut proto::Sticker) {
        input.packId = vec![123; 3];
    }
    fn unknown_pack_id(input: &mut proto::Sticker) {
        input.packId = vec![0xff; 16];
    }
    fn unknown_sticker_id(input: &mut proto::Sticker) {
        input.stickerId = 555555;
    }

    #[test_case(invalid_key, Err(MessageStickerError::InvalidPackKey))]
    #[test_case(no_key, Err(MessageStickerError::InvalidPackKey))]
    #[test_case(invalid_pack_id, Err(MessageStickerError::InvalidPackId))]
    #[test_case(unknown_sticker_id, Ok(()))]
    #[test_case(unknown_pack_id, Ok(()))]
    fn message_sticker(
        mutator: fn(&mut proto::Sticker),
        expected: Result<(), MessageStickerError>,
    ) {
        let mut sticker = proto::Sticker::test_data();
        mutator(&mut sticker);

        let result = sticker.try_into().map(|_: MessageSticker| ());
        assert_eq!(result, expected);
    }
}
