// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::BTreeMap;
use std::fmt::Debug;

use derive_where::derive_where;
use itertools::Itertools as _;

use crate::backup::file::{FilePointer, FilePointerError};
use crate::backup::method::{Lookup, Method};
use crate::backup::serialize::{SerializeOrder, UnorderedList};
use crate::backup::time::ReportUnusualTimestamp;
use crate::backup::{serialize, Color, ColorError, ReferencedTypes, TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

#[derive(serde::Serialize)]
#[derive_where(Debug)]
#[cfg_attr(test, derive_where(PartialEq; M::CustomColorReference: PartialEq, Wallpaper<M>: PartialEq))]
pub struct ChatStyle<M: Method + ReferencedTypes> {
    #[serde(bound(serialize = "Wallpaper<M>: serde::Serialize"))]
    pub wallpaper: Option<Wallpaper<M>>,
    pub bubble_color: BubbleColor<M::CustomColorReference>,
    pub dim_wallpaper_in_dark_mode: bool,
}

#[derive(serde::Serialize)]
#[derive_where(Debug)]
#[cfg_attr(test, derive_where(PartialEq; M::BoxedValue<FilePointer>: PartialEq))]
pub enum Wallpaper<M: Method> {
    Preset(WallpaperPreset),
    Photo(M::BoxedValue<FilePointer>),
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct WallpaperPreset {
    /// Guaranteed to not be [`proto::chat_style::WallpaperPreset::UNKNOWN_WALLPAPER_PRESET`].
    #[serde(serialize_with = "serialize::enum_as_string")]
    enum_value: proto::chat_style::WallpaperPreset,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum BubbleColor<CustomColor> {
    Preset(BubbleColorPreset),
    Custom(CustomColor),
    Auto,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BubbleGradientColor {
    pub color: Color,
    /// guaranteed to be in the range `[0, 1]`
    position: f32,
}

impl SerializeOrder for BubbleGradientColor {
    fn serialize_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.position
            .partial_cmp(&other.position)
            .expect("validated to be non-NaN")
    }
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BubbleColorPreset {
    /// Guaranteed to not be [`proto::chat_style::BubbleColorPreset::UNKNOWN_BUBBLE_COLOR_PRESET`].
    #[allow(unused)]
    #[serde(serialize_with = "serialize::enum_as_string")]
    enum_value: proto::chat_style::BubbleColorPreset,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct CustomColorId(pub(crate) u64);

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CustomChatColor {
    Gradient {
        angle: u32,
        colors: UnorderedList<BubbleGradientColor>,
    },
    Solid {
        color: Color,
    },
}

/// Ordered map of custom colors.
///
/// Uses a `Vec` internally since the list is expected to be small.
#[derive_where(Debug, Default)]
#[cfg_attr(test, derive_where(PartialEq; M::CustomColorData: PartialEq))]
pub struct CustomColorMap<M: ReferencedTypes>(Vec<(CustomColorId, M::CustomColorData)>);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct KeyExists;

impl<M: ReferencedTypes> CustomColorMap<M> {
    fn insert(&mut self, key: CustomColorId, value: M::CustomColorData) -> Result<(), KeyExists> {
        if self.0.iter().any(|(id, _data)| id == &key) {
            return Err(KeyExists);
        }
        self.0.push((key, value));
        Ok(())
    }
}

impl<M: ReferencedTypes> serde::Serialize for CustomColorMap<M> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BTreeMap::from_iter(self.0.iter().map(|(id, data)| (*id, data))).serialize(serializer)
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatStyleError {
    /// ChatStyle.bubbleColor is a oneof but is empty
    NoBubbleColor,
    /// CustomChatColor.color is a oneof but is empty
    NoCustomColor,
    /// found {color_count} colors but {position_count} positions in gradient
    GradientLengthMismatch {
        color_count: usize,
        position_count: usize,
    },
    /// wallpaper preset was UNKNOWN
    UnknownPresetWallpaper,
    /// wallpaper photo: {0}
    WallpaperPhoto(FilePointerError),
    /// bubble preset was UNKNOWN
    UnknownPresetBubbleColor,
    /// found 0 colors and 0 positions in gradient
    GradientEmpty,
    /// chat color was not opaque (ARGB 0x{0:08X})
    ChatColorNotOpaque(u32),
    /// bubble gradient position is invalid: {0}
    InvalidBubbleGradientPosition(f32),
    /// only simple gradients from 0.0 to 1.0 are permitted
    UnsupportedGradient,
    /// referenced unknown custom color ID {0:?}
    UnknownCustomColorId(u64),
    /// 0 is not a valid custom color ID
    InvalidCustomColorId,
    /// duplicate custom color ID {0}
    DuplicateCustomChatColorId(u64),
}

impl<M: ReferencedTypes> TryFrom<Vec<proto::chat_style::CustomChatColor>> for CustomColorMap<M> {
    type Error = ChatStyleError;

    fn try_from(value: Vec<proto::chat_style::CustomChatColor>) -> Result<Self, Self::Error> {
        value
            .into_iter()
            .try_fold(Self::default(), |mut colors, custom_color| {
                let (id, custom_color) = TryFrom::try_from(custom_color)?;
                if id == CustomColorId(0) {
                    return Err(ChatStyleError::InvalidCustomColorId)?;
                }
                colors
                    .insert(id, custom_color.into())
                    .map_err(|KeyExists| ChatStyleError::DuplicateCustomChatColorId(id.0))?;
                Ok(colors)
            })
    }
}

impl<M: ReferencedTypes> Lookup<CustomColorId, M::CustomColorReference> for CustomColorMap<M> {
    fn lookup<'a>(&'a self, key: &'a CustomColorId) -> Option<&'a M::CustomColorReference> {
        self.0
            .iter()
            .find_map(|(id, data)| (id == key).then(|| M::color_reference(id, data)))
    }
}

impl<M: Method + ReferencedTypes> ChatStyle<M> {
    pub fn try_from_proto(
        value: proto::ChatStyle,
        color_map: &impl Lookup<CustomColorId, M::CustomColorReference>,
        context: &dyn ReportUnusualTimestamp,
    ) -> Result<Self, ChatStyleError> {
        let proto::ChatStyle {
            wallpaper,
            bubbleColor,
            dimWallpaperInDarkMode,
            special_fields: _,
        } = value;

        let wallpaper = wallpaper.map(|w| w.try_into_with(context)).transpose()?;

        let bubble_color = bubbleColor
            .ok_or(ChatStyleError::NoBubbleColor)?
            .try_into_with(color_map)?;

        Ok(Self {
            wallpaper,
            bubble_color,
            dim_wallpaper_in_dark_mode: dimWallpaperInDarkMode,
        })
    }
}

impl<C: ReportUnusualTimestamp + ?Sized, M: Method> TryFromWith<proto::chat_style::Wallpaper, C>
    for Wallpaper<M>
{
    type Error = ChatStyleError;

    fn try_from_with(
        value: proto::chat_style::Wallpaper,
        context: &C,
    ) -> Result<Self, Self::Error> {
        Ok(match value {
            proto::chat_style::Wallpaper::WallpaperPreset(preset) => Self::Preset(
                WallpaperPreset::new(preset.enum_value_or_default())
                    .ok_or(ChatStyleError::UnknownPresetWallpaper)?,
            ),
            proto::chat_style::Wallpaper::WallpaperPhoto(photo) => Self::Photo(M::boxed_value(
                photo
                    .try_into_with(context)
                    .map_err(ChatStyleError::WallpaperPhoto)?,
            )),
        })
    }
}

impl<C: Lookup<CustomColorId, CustomColor>, CustomColor: Clone>
    TryFromWith<proto::chat_style::BubbleColor, C> for BubbleColor<CustomColor>
{
    type Error = ChatStyleError;

    fn try_from_with(
        value: proto::chat_style::BubbleColor,
        context: &C,
    ) -> Result<Self, Self::Error> {
        use proto::chat_style::BubbleColor as BubbleColorProto;
        Ok(match value {
            BubbleColorProto::BubbleColorPreset(preset) => Self::Preset(
                BubbleColorPreset::new(preset.enum_value_or_default())
                    .ok_or(ChatStyleError::UnknownPresetBubbleColor)?,
            ),
            BubbleColorProto::CustomColorId(id) => {
                let color_id = CustomColorId(id);
                let Some(color) = context.lookup(&color_id) else {
                    return Err(ChatStyleError::UnknownCustomColorId(id));
                };
                Self::Custom(color.clone())
            }
            BubbleColorProto::AutoBubbleColor(proto::chat_style::AutomaticBubbleColor {
                special_fields: _,
            }) => Self::Auto,
        })
    }
}

impl TryFrom<proto::chat_style::CustomChatColor> for (CustomColorId, CustomChatColor) {
    type Error = ChatStyleError;

    fn try_from(value: proto::chat_style::CustomChatColor) -> Result<Self, Self::Error> {
        let proto::chat_style::CustomChatColor {
            id,
            color,
            special_fields: _,
        } = value;

        let custom_color = color.ok_or(ChatStyleError::NoCustomColor)?.try_into()?;
        Ok((CustomColorId(id), custom_color))
    }
}

impl TryFrom<proto::chat_style::custom_chat_color::Color> for CustomChatColor {
    type Error = ChatStyleError;

    fn try_from(value: proto::chat_style::custom_chat_color::Color) -> Result<Self, Self::Error> {
        use proto::chat_style::custom_chat_color::Color as ColorProto;
        use proto::chat_style::Gradient;

        Ok(match value {
            ColorProto::Gradient(gradient) => {
                let Gradient {
                    angle,
                    colors,
                    positions,
                    special_fields: _,
                } = gradient;

                let color_count = colors.len();
                let position_count = positions.len();
                let colors = match color_count {
                    _ if color_count != position_count => {
                        return Err(ChatStyleError::GradientLengthMismatch {
                            color_count,
                            position_count,
                        });
                    }
                    0 => {
                        return Err(ChatStyleError::GradientEmpty);
                    }
                    2 if positions == [0.0, 1.0] || positions == [1.0, 0.0] => colors
                        .into_iter()
                        .zip(positions)
                        .map(|(color, position)| BubbleGradientColor::new(color, position))
                        .try_collect()?,
                    _ => {
                        // For now, only allow simple gradients with exactly two colors, at 0.0 and 1.0.
                        return Err(ChatStyleError::UnsupportedGradient);
                    }
                };

                CustomChatColor::Gradient { angle, colors }
            }
            ColorProto::Solid(color) => CustomChatColor::Solid {
                color: Color::try_from(color)?,
            },
        })
    }
}

impl From<CustomChatColor> for () {
    fn from(_: CustomChatColor) -> Self {}
}

impl From<ColorError> for ChatStyleError {
    fn from(value: ColorError) -> Self {
        match value {
            ColorError::NotOpaque(color) => ChatStyleError::ChatColorNotOpaque(color),
        }
    }
}

impl WallpaperPreset {
    fn new(preset: proto::chat_style::WallpaperPreset) -> Option<Self> {
        use proto::chat_style::WallpaperPreset;
        match preset {
            WallpaperPreset::UNKNOWN_WALLPAPER_PRESET => None,
            WallpaperPreset::SOLID_BLUSH
            | WallpaperPreset::SOLID_COPPER
            | WallpaperPreset::SOLID_DUST
            | WallpaperPreset::SOLID_CELADON
            | WallpaperPreset::SOLID_RAINFOREST
            | WallpaperPreset::SOLID_PACIFIC
            | WallpaperPreset::SOLID_FROST
            | WallpaperPreset::SOLID_NAVY
            | WallpaperPreset::SOLID_LILAC
            | WallpaperPreset::SOLID_PINK
            | WallpaperPreset::SOLID_EGGPLANT
            | WallpaperPreset::SOLID_SILVER
            | WallpaperPreset::GRADIENT_SUNSET
            | WallpaperPreset::GRADIENT_NOIR
            | WallpaperPreset::GRADIENT_HEATMAP
            | WallpaperPreset::GRADIENT_AQUA
            | WallpaperPreset::GRADIENT_IRIDESCENT
            | WallpaperPreset::GRADIENT_MONSTERA
            | WallpaperPreset::GRADIENT_BLISS
            | WallpaperPreset::GRADIENT_SKY
            | WallpaperPreset::GRADIENT_PEACH => Some(Self { enum_value: preset }),
        }
    }
}

impl BubbleColorPreset {
    fn new(preset: proto::chat_style::BubbleColorPreset) -> Option<Self> {
        use proto::chat_style::BubbleColorPreset as BubbleColorPresetProto;
        match preset {
            BubbleColorPresetProto::UNKNOWN_BUBBLE_COLOR_PRESET => None,
            BubbleColorPresetProto::SOLID_ULTRAMARINE
            | BubbleColorPresetProto::SOLID_CRIMSON
            | BubbleColorPresetProto::SOLID_VERMILION
            | BubbleColorPresetProto::SOLID_BURLAP
            | BubbleColorPresetProto::SOLID_FOREST
            | BubbleColorPresetProto::SOLID_WINTERGREEN
            | BubbleColorPresetProto::SOLID_TEAL
            | BubbleColorPresetProto::SOLID_BLUE
            | BubbleColorPresetProto::SOLID_INDIGO
            | BubbleColorPresetProto::SOLID_VIOLET
            | BubbleColorPresetProto::SOLID_PLUM
            | BubbleColorPresetProto::SOLID_TAUPE
            | BubbleColorPresetProto::SOLID_STEEL
            | BubbleColorPresetProto::GRADIENT_EMBER
            | BubbleColorPresetProto::GRADIENT_MIDNIGHT
            | BubbleColorPresetProto::GRADIENT_INFRARED
            | BubbleColorPresetProto::GRADIENT_LAGOON
            | BubbleColorPresetProto::GRADIENT_FLUORESCENT
            | BubbleColorPresetProto::GRADIENT_BASIL
            | BubbleColorPresetProto::GRADIENT_SUBLIME
            | BubbleColorPresetProto::GRADIENT_SEA
            | BubbleColorPresetProto::GRADIENT_TANGERINE => Some(Self { enum_value: preset }),
        }
    }
}

impl BubbleGradientColor {
    fn new(color: u32, position: f32) -> Result<Self, ChatStyleError> {
        let color = Color::try_from(color)?;
        if !(0.0..=1.0).contains(&position) {
            return Err(ChatStyleError::InvalidBubbleGradientPosition(position));
        }
        Ok(Self { color, position })
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use test_case::test_case;

    use super::*;
    use crate::backup::chat::chat_style::Color;
    use crate::backup::method::{Store, ValidateOnly};
    use crate::backup::testutil::TestContext;

    impl proto::ChatStyle {
        fn test_data() -> Self {
            Self {
                wallpaper: Some(proto::chat_style::Wallpaper::test_data()),
                bubbleColor: Some(proto::chat_style::BubbleColor::AutoBubbleColor(
                    Default::default(),
                )),
                dimWallpaperInDarkMode: true,
                special_fields: Default::default(),
            }
        }
    }

    impl proto::chat_style::Wallpaper {
        fn test_data() -> Self {
            proto::chat_style::Wallpaper::WallpaperPreset(
                proto::chat_style::WallpaperPreset::GRADIENT_AQUA.into(),
            )
        }
    }

    impl proto::chat_style::CustomChatColor {
        pub(crate) const TEST_ID: CustomColorId = CustomColorId(333);
        pub(crate) fn test_data() -> Self {
            Self {
                id: Self::TEST_ID.0,
                color: Some(proto::chat_style::custom_chat_color::Color::Solid(
                    0xFF123456,
                )),
                special_fields: Default::default(),
            }
        }
    }

    impl CustomChatColor {
        pub(crate) fn from_proto_test_data() -> Self {
            Self::Solid {
                color: Color(0xFF123456),
            }
        }
    }

    impl<M: ReferencedTypes> CustomColorMap<M> {
        pub(crate) fn from_proto_test_data() -> Self {
            Self(vec![(
                proto::chat_style::CustomChatColor::TEST_ID,
                CustomChatColor::from_proto_test_data().into(),
            )])
        }
    }

    #[test]
    fn valid_chat_style() {
        let test_context = TestContext::default();
        assert_eq!(
            ChatStyle::try_from_proto(proto::ChatStyle::test_data(), &test_context, &test_context),
            Ok(ChatStyle::<Store> {
                wallpaper: Some(Wallpaper::Preset(WallpaperPreset {
                    enum_value: proto::chat_style::WallpaperPreset::GRADIENT_AQUA
                })),
                bubble_color: BubbleColor::Auto,
                dim_wallpaper_in_dark_mode: true,
            })
        )
    }

    #[test]
    fn valid_gradient() {
        assert_eq!(
            proto::chat_style::custom_chat_color::Color::Gradient(proto::chat_style::Gradient {
                angle: 123,
                colors: vec![0xFF005555, 0xFF009999],
                positions: vec![1.0, 0.0],
                special_fields: Default::default(),
            })
            .try_into(),
            Ok(CustomChatColor::Gradient {
                angle: 123,
                colors: vec![
                    BubbleGradientColor {
                        color: Color(0xFF005555),
                        position: 1.0,
                    },
                    BubbleGradientColor {
                        color: Color(0xFF009999),
                        position: 0.0,
                    },
                ]
                .into(),
            })
        );
    }

    #[test]
    fn valid_custom_chat_color() {
        assert_eq!(
            proto::chat_style::CustomChatColor::test_data().try_into(),
            Ok((
                proto::chat_style::CustomChatColor::TEST_ID,
                CustomChatColor::from_proto_test_data()
            ))
        );
    }

    fn uneven_gradient(proto: &mut proto::chat_style::CustomChatColor) {
        proto.set_gradient(proto::chat_style::Gradient {
            colors: vec![0xFFFFFFFF; 3],
            positions: vec![0.0; 2],
            ..Default::default()
        });
    }
    fn empty_gradient(proto: &mut proto::chat_style::CustomChatColor) {
        proto.set_gradient(Default::default())
    }
    fn invalid_gradient_position(proto: &mut proto::chat_style::CustomChatColor) {
        proto.set_gradient(proto::chat_style::Gradient {
            colors: vec![0xFFFFFFFF, 0xFF000000],
            positions: vec![-1.0, 1.0],
            ..Default::default()
        });
    }
    fn complex_gradient(proto: &mut proto::chat_style::CustomChatColor) {
        proto.set_gradient(proto::chat_style::Gradient {
            colors: vec![0xFFFFFFFF, 0xFF000000, 0xFFFFFFFF],
            positions: vec![0.0, 0.5, 1.0],
            ..Default::default()
        });
    }
    fn non_opaque_color(proto: &mut proto::chat_style::CustomChatColor) {
        proto.set_solid(0);
    }

    #[test_case(uneven_gradient, ChatStyleError::GradientLengthMismatch {color_count: 3, position_count: 2})]
    #[test_case(empty_gradient, ChatStyleError::GradientEmpty)]
    #[test_case(complex_gradient, ChatStyleError::UnsupportedGradient)]
    #[test_case(invalid_gradient_position, ChatStyleError::UnsupportedGradient)]
    #[test_case(non_opaque_color, ChatStyleError::ChatColorNotOpaque(0))]
    fn custom_color(
        modifier: fn(&mut proto::chat_style::CustomChatColor),
        expected_err: ChatStyleError,
    ) {
        let mut proto = proto::chat_style::CustomChatColor::test_data();
        modifier(&mut proto);
        let result = proto
            .try_into()
            .map(|_: (CustomColorId, CustomChatColor)| ());

        assert_eq!(result, Err(expected_err))
    }

    #[test_case(|x| x.wallpaper = None => Ok(()); "no wallpaper")]
    #[test_case(|x| x.bubbleColor = None => Err(ChatStyleError::NoBubbleColor); "no bubble color")]
    #[test_case(
        |x| x.set_customColorId(333333333) =>
        Err(ChatStyleError::UnknownCustomColorId(333333333));
        "invalid custom color id"
    )]
    #[test_case(
        |x| x.set_wallpaperPreset(proto::chat_style::WallpaperPreset::UNKNOWN_WALLPAPER_PRESET) =>
        Err(ChatStyleError::UnknownPresetWallpaper);
        "unknown wallpaper preset"
    )]
    #[test_case(|x| x.set_wallpaperPhoto(proto::FilePointer::test_data()) => Ok(()); "wallpaper photo")]
    #[test_case(
        |x| x.set_wallpaperPhoto(proto::FilePointer::default()) =>
        Err(ChatStyleError::WallpaperPhoto(FilePointerError::NoLocator));
        "invalid wallpaper photo"
    )]
    #[test_case(
        |x| x.set_bubbleColorPreset(proto::chat_style::BubbleColorPreset::UNKNOWN_BUBBLE_COLOR_PRESET) =>
        Err(ChatStyleError::UnknownPresetBubbleColor);
        "unknown bubble preset"
    )]
    fn chat_style(modifier: fn(&mut proto::ChatStyle)) -> Result<(), ChatStyleError> {
        let mut proto = proto::ChatStyle::test_data();
        modifier(&mut proto);
        let test_context = TestContext::default();
        ChatStyle::try_from_proto(proto, &test_context, &test_context).map(|_: ChatStyle<Store>| ())
    }

    #[test]
    fn custom_color_map_sorts_when_serializing() {
        let color1 = Arc::new(CustomChatColor::Solid { color: Color(100) });
        let color2 = Arc::new(CustomChatColor::Solid { color: Color(22) });

        let map1 = CustomColorMap::<Store>(vec![
            (CustomColorId(1), color1.clone()),
            (CustomColorId(2), color2.clone()),
        ]);
        let map2 =
            CustomColorMap::<Store>(vec![(CustomColorId(2), color2), (CustomColorId(1), color1)]);

        assert_eq!(
            serde_json::to_string_pretty(&map1).expect("valid"),
            serde_json::to_string_pretty(&map2).expect("valid"),
        );
    }

    #[test]
    fn custom_color_map_rejects_duplicates() {
        assert_eq!(
            CustomColorMap::<ValidateOnly>::try_from(vec![
                proto::chat_style::CustomChatColor::test_data(),
                proto::chat_style::CustomChatColor::test_data(),
            ])
            .expect_err("should have failed"),
            ChatStyleError::DuplicateCustomChatColorId(
                proto::chat_style::CustomChatColor::TEST_ID.0,
            )
        )
    }

    #[test]
    fn custom_color_map_rejects_id_zero() {
        assert_eq!(
            CustomColorMap::<ValidateOnly>::try_from(vec![proto::chat_style::CustomChatColor {
                id: 0,
                ..proto::chat_style::CustomChatColor::test_data()
            },])
            .expect_err("should have failed"),
            ChatStyleError::InvalidCustomColorId
        )
    }
}
