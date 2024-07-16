// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;

use derive_where::derive_where;
use itertools::Itertools as _;

use crate::backup::method::{Contains, Lookup};
use crate::backup::{serialize, ReferencedTypes, TryFromWith, TryIntoWith as _};
use crate::proto::backup as proto;

#[derive(serde::Serialize)]
#[derive_where(Debug)]
#[cfg_attr(test, derive_where(PartialEq; M::CustomColorReference: PartialEq))]
pub struct ChatStyle<M: ReferencedTypes> {
    pub wallpaper: Option<Wallpaper>,
    pub bubble_color: BubbleColor<M::CustomColorReference>,
    pub dim_wallpaper_in_dark_mode: bool,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Wallpaper {
    Preset(WallpaperPreset),
    Photo,
}

#[derive(Copy, Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(transparent)]
pub struct Color(u32);

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
    #[allow(unused)]
    position: f32,
}

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BubbleColorPreset {
    /// Guaranteed to not be [`proto::chat_style::BubbleColorPreset::UNKNOWN_BUBBLE_COLOR_PRESET`].
    #[allow(unused)]
    #[serde(serialize_with = "serialize::enum_as_string")]
    enum_value: proto::chat_style::BubbleColorPreset,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
pub struct CustomColorId(pub(crate) u32);

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum CustomChatColor {
    Gradient {
        angle: u32,
        colors: Vec<BubbleGradientColor>,
    },
    Solid {
        color: Color,
    },
}

/// Ordered map of custom colors.
///
/// Uses a `Vec` internally since the list is expected to be small.
#[derive_where(Debug, Default)]
#[derive(serde::Serialize)]
#[cfg_attr(test, derive_where(PartialEq; M::CustomColorData: PartialEq))]
pub struct CustomColorMap<M: ReferencedTypes>(Vec<(CustomColorId, M::CustomColorData)>);

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
    /// bubble preset was UNKNOWN
    UnknownPresetBubbleColor,
    /// found 0 colors and 0 positions in gradient
    GradientEmpty,
    /// bubble gradient position is invalid: {0}
    InvalidBubbleGradientPosition(f32),
    /// referenced unknown custom color ID {0:?}
    UnknownCustomColorId(u32),
    /// duplicate custom color ID {0}
    DuplicateCustomChatColorId(u32),
}

impl<M: ReferencedTypes> TryFrom<Vec<proto::chat_style::CustomChatColor>> for CustomColorMap<M> {
    type Error = ChatStyleError;

    fn try_from(value: Vec<proto::chat_style::CustomChatColor>) -> Result<Self, Self::Error> {
        value
            .into_iter()
            .try_fold(Self::default(), |mut colors, custom_color| {
                let (id, custom_color) = TryFrom::try_from(custom_color)?;
                if colors.contains(&id) {
                    return Err(ChatStyleError::DuplicateCustomChatColorId(id.0));
                }
                colors.0.push((id, custom_color.into()));
                Ok(colors)
            })
    }
}

impl<M: ReferencedTypes> Contains<CustomColorId> for CustomColorMap<M> {
    fn contains(&self, key: &CustomColorId) -> bool {
        self.0.iter().any(|(id, _value)| id == key)
    }
}

impl<M: ReferencedTypes> Lookup<CustomColorId, M::CustomColorReference> for CustomColorMap<M> {
    fn lookup<'a>(&'a self, key: &'a CustomColorId) -> Option<&'a M::CustomColorReference> {
        self.0
            .iter()
            .find_map(|(id, data)| (id == key).then(|| M::color_reference(id, data)))
    }
}

impl<C: Lookup<CustomColorId, M::CustomColorReference>, M: ReferencedTypes>
    TryFromWith<proto::ChatStyle, C> for ChatStyle<M>
{
    type Error = ChatStyleError;

    fn try_from_with(value: proto::ChatStyle, context: &C) -> Result<Self, Self::Error> {
        let proto::ChatStyle {
            wallpaper,
            bubbleColor,
            dimWallpaperInDarkMode,
            special_fields: _,
        } = value;

        let wallpaper = wallpaper.map(TryInto::try_into).transpose()?;

        let bubble_color = bubbleColor
            .ok_or(ChatStyleError::NoBubbleColor)?
            .try_into_with(context)?;

        Ok(Self {
            wallpaper,
            bubble_color,
            dim_wallpaper_in_dark_mode: dimWallpaperInDarkMode,
        })
    }
}

impl TryFrom<proto::chat_style::Wallpaper> for Wallpaper {
    type Error = ChatStyleError;

    fn try_from(value: proto::chat_style::Wallpaper) -> Result<Self, Self::Error> {
        Ok(match value {
            proto::chat_style::Wallpaper::WallpaperPreset(preset) => Self::Preset(
                WallpaperPreset::new(preset.enum_value_or_default())
                    .ok_or(ChatStyleError::UnknownPresetWallpaper)?,
            ),
            proto::chat_style::Wallpaper::WallpaperPhoto(photo) => {
                // TODO validate this field.
                let _photo = photo;
                Self::Photo
            }
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
                let colors = if color_count != position_count {
                    return Err(ChatStyleError::GradientLengthMismatch {
                        color_count,
                        position_count,
                    });
                } else if color_count == 0 {
                    return Err(ChatStyleError::GradientEmpty);
                } else {
                    colors
                        .into_iter()
                        .zip(positions)
                        .map(|(color, position)| {
                            BubbleGradientColor::new(color, position)
                                .ok_or(ChatStyleError::InvalidBubbleGradientPosition(position))
                        })
                        .try_collect()?
                };

                CustomChatColor::Gradient { angle, colors }
            }
            ColorProto::Solid(color) => CustomChatColor::Solid {
                color: Color(color),
            },
        })
    }
}

impl From<CustomChatColor> for () {
    fn from(_: CustomChatColor) -> Self {}
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
    fn new(color: u32, position: f32) -> Option<Self> {
        (0.0..=1.0).contains(&position).then_some(Self {
            color: Color(color),
            position,
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use crate::backup::chat::chat_style::Color;
    use crate::backup::chat::testutil::TestContext;
    use crate::backup::method::Store;

    use super::*;

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
                color: Some(proto::chat_style::custom_chat_color::Color::Solid(123456)),
                special_fields: Default::default(),
            }
        }
    }

    impl CustomChatColor {
        pub(crate) fn from_proto_test_data() -> Self {
            Self::Solid {
                color: Color(123456),
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
        assert_eq!(
            proto::ChatStyle::test_data().try_into_with(&TestContext::default()),
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
                colors: vec![555],
                positions: vec![0.5],
                special_fields: Default::default(),
            })
            .try_into(),
            Ok(CustomChatColor::Gradient {
                angle: 123,
                colors: vec![BubbleGradientColor {
                    color: Color(555),
                    position: 0.5
                }]
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
            colors: vec![1; 3],
            positions: vec![0.0; 2],
            ..Default::default()
        });
    }
    fn empty_gradient(proto: &mut proto::chat_style::CustomChatColor) {
        proto.set_gradient(Default::default())
    }
    fn invalid_gradient_position(proto: &mut proto::chat_style::CustomChatColor) {
        proto.set_gradient(proto::chat_style::Gradient {
            colors: vec![1],
            positions: vec![-1.0],
            ..Default::default()
        });
    }

    #[test_case(uneven_gradient, ChatStyleError::GradientLengthMismatch {color_count: 3, position_count: 2})]
    #[test_case(empty_gradient, ChatStyleError::GradientEmpty)]
    #[test_case(invalid_gradient_position, ChatStyleError::InvalidBubbleGradientPosition(-1.0))]
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

    fn no_wallpaper(proto: &mut proto::ChatStyle) {
        proto.wallpaper = None;
    }
    fn no_bubble_color(proto: &mut proto::ChatStyle) {
        proto.bubbleColor = None;
    }
    fn invalid_custom_color_id(proto: &mut proto::ChatStyle) {
        proto.set_customColorId(333333333);
    }
    fn unknown_wallpaper_preset(proto: &mut proto::ChatStyle) {
        proto.set_wallpaperPreset(proto::chat_style::WallpaperPreset::UNKNOWN_WALLPAPER_PRESET);
    }
    fn unknown_bubble_preset(proto: &mut proto::ChatStyle) {
        proto.set_bubbleColorPreset(
            proto::chat_style::BubbleColorPreset::UNKNOWN_BUBBLE_COLOR_PRESET,
        );
    }

    #[test_case(no_wallpaper, Ok(()))]
    #[test_case(no_bubble_color, Err(ChatStyleError::NoBubbleColor))]
    #[test_case(
        invalid_custom_color_id,
        Err(ChatStyleError::UnknownCustomColorId(333333333))
    )]
    #[test_case(unknown_wallpaper_preset, Err(ChatStyleError::UnknownPresetWallpaper))]
    #[test_case(unknown_bubble_preset, Err(ChatStyleError::UnknownPresetBubbleColor))]
    fn chat_style(
        modifier: fn(&mut proto::ChatStyle),
        expected_result: Result<(), ChatStyleError>,
    ) {
        let mut proto = proto::ChatStyle::test_data();
        modifier(&mut proto);
        let result = proto
            .try_into_with(&TestContext::default())
            .map(|_: ChatStyle<Store>| ());

        assert_eq!(result, expected_result)
    }
}
