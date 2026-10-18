//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;

use crate::backup::TryIntoWith;
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::sticker::{Key, PackId};
use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::proto::backup as proto;

/// The most stickers a [`proto::FavoriteStickerList`] may hold.
const MAX_FAVORITE_STICKERS: usize = 500;

/// Validated version of [`proto::FavoriteStickerList`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct FavoriteStickerList {
    pub stickers: UnorderedList<FavoriteSticker>,
    _limit_construction_to_module: (),
}

/// Validated version of [`proto::favorite_sticker_list::FavoriteSticker`].
#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct FavoriteSticker {
    pub pack_id: PackId,
    pub pack_key: Key,
    pub sticker_id: u32,
    pub favorited_at: Timestamp,
    _limit_construction_to_module: (),
}

impl SerializeOrder for FavoriteSticker {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.favorited_at
            .cmp(&other.favorited_at)
            .then_with(|| self.pack_id.cmp(&other.pack_id))
            .then_with(|| self.sticker_id.cmp(&other.sticker_id))
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum FavoriteStickerListError {
    /// {0} favorite stickers is more than the maximum of 500
    TooManyStickers(usize),
    /// favorite sticker {index}: {error}
    Sticker {
        index: usize,
        error: FavoriteStickerError,
    },
    /// sticker {1} from pack {0:?} is in the list more than once
    DuplicateSticker(PackId, u32),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
#[expect(clippy::enum_variant_names)]
pub enum FavoriteStickerError {
    /// pack ID is invalid
    InvalidPackId,
    /// pack key is invalid
    InvalidPackKey,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl<C: ReportUnusualTimestamp> TryIntoWith<FavoriteStickerList, C> for proto::FavoriteStickerList {
    type Error = FavoriteStickerListError;

    fn try_into_with(self, context: &C) -> Result<FavoriteStickerList, Self::Error> {
        let proto::FavoriteStickerList {
            favoriteSticker,
            special_fields: _,
        } = self;

        if favoriteSticker.len() > MAX_FAVORITE_STICKERS {
            return Err(FavoriteStickerListError::TooManyStickers(
                favoriteSticker.len(),
            ));
        }

        let mut seen = HashSet::with_capacity(favoriteSticker.len());
        let mut stickers = Vec::with_capacity(favoriteSticker.len());
        for (index, favorite) in favoriteSticker.into_iter().enumerate() {
            let favorite: FavoriteSticker = favorite
                .try_into_with(context)
                .map_err(|error| FavoriteStickerListError::Sticker { index, error })?;

            let pack_id = favorite.pack_id;
            let sticker_id = favorite.sticker_id;
            if !seen.insert((pack_id, sticker_id)) {
                return Err(FavoriteStickerListError::DuplicateSticker(
                    pack_id, sticker_id,
                ));
            }

            stickers.push(favorite);
        }

        Ok(FavoriteStickerList {
            stickers: stickers.into(),
            _limit_construction_to_module: (),
        })
    }
}

impl<C: ReportUnusualTimestamp> TryIntoWith<FavoriteSticker, C>
    for proto::favorite_sticker_list::FavoriteSticker
{
    type Error = FavoriteStickerError;

    fn try_into_with(self, context: &C) -> Result<FavoriteSticker, Self::Error> {
        let proto::favorite_sticker_list::FavoriteSticker {
            packId,
            packKey,
            stickerId,
            favoritedAtTimestamp,
            special_fields: _,
        } = self;

        let pack_id = packId
            .as_slice()
            .try_into()
            .map_err(|_| FavoriteStickerError::InvalidPackId)?;

        let pack_key = packKey
            .try_into()
            .map_err(|_| FavoriteStickerError::InvalidPackKey)?;

        let favorited_at = Timestamp::from_millis(
            favoritedAtTimestamp,
            "FavoriteSticker.favoritedAtTimestamp",
            context,
        )?;

        Ok(FavoriteSticker {
            pack_id,
            pack_key,
            sticker_id: stickerId,
            favorited_at,
            _limit_construction_to_module: (),
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;
    use crate::backup::testutil::TestContext;

    impl proto::favorite_sticker_list::FavoriteSticker {
        const TEST_FAVORITED_AT_MS: u64 = 1_700_000_000_000;

        fn test_data() -> Self {
            let proto::StickerPack {
                packId,
                packKey,
                special_fields: _,
            } = proto::StickerPack::test_data();
            Self {
                packId,
                packKey,
                stickerId: proto::Sticker::TEST_ID,
                favoritedAtTimestamp: Self::TEST_FAVORITED_AT_MS,
                ..Default::default()
            }
        }

        fn test_data_with_sticker_id(sticker_id: u32) -> Self {
            Self {
                stickerId: sticker_id,
                ..Self::test_data()
            }
        }
    }

    impl proto::FavoriteStickerList {
        pub(crate) fn test_data() -> Self {
            Self {
                favoriteSticker: vec![
                    proto::favorite_sticker_list::FavoriteSticker::test_data_with_sticker_id(1),
                    proto::favorite_sticker_list::FavoriteSticker::test_data_with_sticker_id(2),
                ],
                ..Default::default()
            }
        }
    }

    #[test]
    fn valid_favorite_sticker_list() {
        let list: FavoriteStickerList = proto::FavoriteStickerList::test_data()
            .try_into_with(&TestContext::default())
            .expect("valid");

        let ids: Vec<_> = list
            .stickers
            .iter()
            .map(|favorite| favorite.sticker_id)
            .collect();
        assert_eq!(ids, [1, 2]);
        assert!(list.stickers.iter().all(|favorite| {
            favorite.favorited_at.as_millis()
                == proto::favorite_sticker_list::FavoriteSticker::TEST_FAVORITED_AT_MS
        }));
    }

    #[test]
    fn empty_list_is_valid() {
        let list: FavoriteStickerList = proto::FavoriteStickerList::default()
            .try_into_with(&TestContext::default())
            .expect("valid");
        assert!(list.stickers.is_empty());
    }

    #[test_case(MAX_FAVORITE_STICKERS => Ok(()); "at limit")]
    #[test_case(MAX_FAVORITE_STICKERS + 1 => Err(FavoriteStickerListError::TooManyStickers(MAX_FAVORITE_STICKERS + 1)); "over limit")]
    fn sticker_count(count: usize) -> Result<(), FavoriteStickerListError> {
        let sticker_ids = 0..u32::try_from(count).expect("small");
        proto::FavoriteStickerList {
            favoriteSticker: sticker_ids
                .map(proto::favorite_sticker_list::FavoriteSticker::test_data_with_sticker_id)
                .collect(),
            ..Default::default()
        }
        .try_into_with(&TestContext::default())
        .map(|_: FavoriteStickerList| ())
    }

    #[test]
    fn too_many_is_checked_before_stickers() {
        let favorite = proto::favorite_sticker_list::FavoriteSticker {
            packId: vec![],
            ..proto::favorite_sticker_list::FavoriteSticker::test_data()
        };
        assert_eq!(
            proto::FavoriteStickerList {
                favoriteSticker: vec![favorite; MAX_FAVORITE_STICKERS + 1],
                ..Default::default()
            }
            .try_into_with(&TestContext::default())
            .map(|_: FavoriteStickerList| ()),
            Err(FavoriteStickerListError::TooManyStickers(
                MAX_FAVORITE_STICKERS + 1
            ))
        );
    }

    #[test]
    fn rejects_duplicate_sticker() {
        let mut list = proto::FavoriteStickerList::test_data();
        let mut duplicate =
            proto::favorite_sticker_list::FavoriteSticker::test_data_with_sticker_id(1);
        // A different key doesn't make it a different sticker.
        duplicate.packKey = vec![0x44; 32];
        list.favoriteSticker.push(duplicate);

        assert_eq!(
            list.try_into_with(&TestContext::default())
                .map(|_: FavoriteStickerList| ()),
            Err(FavoriteStickerListError::DuplicateSticker(
                proto::StickerPack::TEST_ID,
                1
            ))
        );
    }

    #[test]
    fn same_sticker_id_in_different_packs_is_not_a_duplicate() {
        let mut list = proto::FavoriteStickerList::test_data();
        list.favoriteSticker
            .push(proto::favorite_sticker_list::FavoriteSticker {
                packId: vec![0x33; 16],
                stickerId: 1,
                ..proto::favorite_sticker_list::FavoriteSticker::test_data()
            });

        assert_eq!(
            list.try_into_with(&TestContext::default())
                .map(|_: FavoriteStickerList| ()),
            Ok(())
        );
    }

    #[test]
    fn invalid_sticker_reports_index() {
        let mut list = proto::FavoriteStickerList::test_data();
        list.favoriteSticker[1].packKey = vec![];

        assert_eq!(
            list.try_into_with(&TestContext::default())
                .map(|_: FavoriteStickerList| ()),
            Err(FavoriteStickerListError::Sticker {
                index: 1,
                error: FavoriteStickerError::InvalidPackKey,
            })
        );
    }

    #[test_case(|_| {} => Ok(()); "valid")]
    #[test_case(|x| x.packId = vec![123; 3] => Err(FavoriteStickerError::InvalidPackId); "invalid pack ID")]
    #[test_case(|x| x.packId = vec![] => Err(FavoriteStickerError::InvalidPackId); "no pack ID")]
    #[test_case(|x| x.packKey = vec![0xaa; 45] => Err(FavoriteStickerError::InvalidPackKey); "invalid pack key")]
    #[test_case(|x| x.packKey = vec![] => Err(FavoriteStickerError::InvalidPackKey); "no pack key")]
    #[test_case(|x| x.stickerId = 0 => Ok(()); "sticker ID zero")]
    #[test_case(
        |x| x.favoritedAtTimestamp = Timestamp::INVALID_TIMESTAMP_MS =>
        Err(FavoriteStickerError::InvalidTimestamp(TimestampError(
            "FavoriteSticker.favoritedAtTimestamp",
            Timestamp::INVALID_TIMESTAMP_MS
        )));
        "invalid timestamp"
    )]
    fn favorite_sticker(
        mutator: fn(&mut proto::favorite_sticker_list::FavoriteSticker),
    ) -> Result<(), FavoriteStickerError> {
        let mut favorite = proto::favorite_sticker_list::FavoriteSticker::test_data();
        mutator(&mut favorite);

        favorite
            .try_into_with(&TestContext::default())
            .map(|_: FavoriteSticker| ())
    }
}
