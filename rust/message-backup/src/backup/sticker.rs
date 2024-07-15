//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Silence clippy's complains about private fields used to prevent construction
// and recommends `#[non_exhaustive]`. The annotation only applies outside this
// crate, but we want intra-crate privacy.
#![allow(clippy::manual_non_exhaustive)]

use derive_where::derive_where;

use crate::backup::method::Method;
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
    pub emoji: Option<String>,
    _limit_construction_to_module: (),
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, serde::Serialize)]
pub struct PackId([u8; 16]);

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
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

    #[test_case(invalid_key, Err(StickerPackError::InvalidKey))]
    #[test_case(no_key, Err(StickerPackError::InvalidKey))]
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
    fn invalid_key(pack: &mut impl StickerPackFields) {
        *pack.pack_key_mut() = vec![0xaa; 45];
    }
    fn no_key(pack: &mut impl StickerPackFields) {
        *pack.pack_key_mut() = vec![];
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
