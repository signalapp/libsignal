// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use itertools::Itertools as _;

use crate::proto::backup as proto;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ChatStyle {
    pub wallpaper: Wallpaper,
    pub bubble_color: BubbleColor,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Wallpaper {
    Preset(WallpaperPreset),
    Photo,
}

#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Color(#[allow(unused)] u32);

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct WallpaperPreset {
    /// Guaranteed to not be [`proto::chat_style::WallpaperPreset::UNKNOWN_WALLPAPER_PRESET`].
    #[allow(unused)]
    enum_value: proto::chat_style::WallpaperPreset,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum BubbleColor {
    Preset(BubbleColorPreset),
    Gradient {
        angle: u32,
        colors: Vec<BubbleGradientColor>,
    },
    Solid {
        color: Color,
    },
    Auto,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BubbleGradientColor {
    pub color: Color,
    /// guaranteed to be in the range `[0, 1]`
    #[allow(unused)]
    position: f32,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BubbleColorPreset {
    /// Guaranteed to not be [`proto::chat_style::BubbleColorPreset::UNKNOWN_BUBBLE_COLOR_PRESET`].
    #[allow(unused)]
    enum_value: proto::chat_style::BubbleColorPreset,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ChatStyleError {
    /// ChatStyle.wallpaper is a oneof but is empty
    NoWallpaper,
    /// ChatStyle.bubbleColor is a oneof but is empty
    NoBubbleColor,
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
}

impl TryFrom<proto::ChatStyle> for ChatStyle {
    type Error = ChatStyleError;

    fn try_from(value: proto::ChatStyle) -> Result<Self, Self::Error> {
        let proto::ChatStyle {
            wallpaper,
            bubbleColor,
            special_fields: _,
        } = value;

        let wallpaper = wallpaper.ok_or(ChatStyleError::NoWallpaper)?.try_into()?;

        let bubble_color = bubbleColor
            .ok_or(ChatStyleError::NoBubbleColor)?
            .try_into()?;

        Ok(Self {
            wallpaper,
            bubble_color,
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

impl TryFrom<proto::chat_style::BubbleColor> for BubbleColor {
    type Error = ChatStyleError;

    fn try_from(value: proto::chat_style::BubbleColor) -> Result<Self, Self::Error> {
        use proto::chat_style::{BubbleColor as BubbleColorProto, Gradient};
        Ok(match value {
            BubbleColorProto::BubbleColorPreset(preset) => Self::Preset(
                BubbleColorPreset::new(preset.enum_value_or_default())
                    .ok_or(ChatStyleError::UnknownPresetBubbleColor)?,
            ),
            BubbleColorProto::BubbleGradient(gradient) => {
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

                Self::Gradient { angle, colors }
            }
            BubbleColorProto::BubbleSolidColor(color) => Self::Solid {
                color: Color(color),
            },
            BubbleColorProto::AutoBubbleColor(proto::chat_style::AutomaticBubbleColor {
                special_fields: _,
            }) => Self::Auto,
        })
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

    use super::*;

    impl proto::ChatStyle {
        fn test_data() -> Self {
            Self {
                wallpaper: Some(proto::chat_style::Wallpaper::test_data()),
                bubbleColor: Some(proto::chat_style::BubbleColor::AutoBubbleColor(
                    Default::default(),
                )),
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

    #[test]
    fn valid_chat_style() {
        assert_eq!(
            proto::ChatStyle::test_data().try_into(),
            Ok(ChatStyle {
                wallpaper: Wallpaper::Preset(WallpaperPreset {
                    enum_value: proto::chat_style::WallpaperPreset::GRADIENT_AQUA
                }),
                bubble_color: BubbleColor::Auto,
            })
        )
    }

    fn no_wallpaper(proto: &mut proto::ChatStyle) {
        proto.wallpaper = None;
    }
    fn no_bubble_color(proto: &mut proto::ChatStyle) {
        proto.bubbleColor = None;
    }
    fn uneven_gradient(proto: &mut proto::ChatStyle) {
        proto.set_bubbleGradient(proto::chat_style::Gradient {
            colors: vec![1; 3],
            positions: vec![0.0; 2],
            ..Default::default()
        });
    }
    fn unknown_wallpaper_preset(proto: &mut proto::ChatStyle) {
        proto.set_wallpaperPreset(proto::chat_style::WallpaperPreset::UNKNOWN_WALLPAPER_PRESET);
    }
    fn unknown_bubble_preset(proto: &mut proto::ChatStyle) {
        proto.set_bubbleColorPreset(
            proto::chat_style::BubbleColorPreset::UNKNOWN_BUBBLE_COLOR_PRESET,
        );
    }
    fn empty_gradient(proto: &mut proto::ChatStyle) {
        proto.set_bubbleGradient(Default::default())
    }
    fn invalid_gradient_position(proto: &mut proto::ChatStyle) {
        proto.set_bubbleGradient(proto::chat_style::Gradient {
            colors: vec![1],
            positions: vec![-1.0],
            ..Default::default()
        });
    }

    #[test]
    fn bubble_gradient() {
        assert_eq!(
            proto::chat_style::BubbleColor::BubbleGradient(proto::chat_style::Gradient {
                angle: 123,
                colors: vec![555],
                positions: vec![0.5],
                special_fields: Default::default(),
            })
            .try_into(),
            Ok(BubbleColor::Gradient {
                angle: 123,
                colors: vec![BubbleGradientColor {
                    color: Color(555),
                    position: 0.5
                }]
            })
        );
    }

    #[test_case(no_wallpaper, ChatStyleError::NoWallpaper)]
    #[test_case(no_bubble_color, ChatStyleError::NoBubbleColor)]
    #[test_case(uneven_gradient, ChatStyleError::GradientLengthMismatch {color_count: 3, position_count: 2})]
    #[test_case(unknown_wallpaper_preset, ChatStyleError::UnknownPresetWallpaper)]
    #[test_case(unknown_bubble_preset, ChatStyleError::UnknownPresetBubbleColor)]
    #[test_case(empty_gradient, ChatStyleError::GradientEmpty)]
    #[test_case(invalid_gradient_position, ChatStyleError::InvalidBubbleGradientPosition(-1.0))]
    fn chat_style(modifier: fn(&mut proto::ChatStyle), expected_err: ChatStyleError) {
        let mut proto = proto::ChatStyle::test_data();
        modifier(&mut proto);
        let result = proto.try_into().map(|_: ChatStyle| ());

        assert_eq!(result, Err(expected_err))
    }
}
