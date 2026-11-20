//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Type-directed ways to bridge integers to the various app languages.

use std::fmt::Debug;
use std::num::NonZeroU8;

// Derive Copy to ensure that this error is cheap (at least in code size terms).
#[derive(Debug, displaydoc::Display, Clone, Copy)]
pub enum OutOfRange {
    /// value with bit width {bit_width_of_value} out of range for UInt<{bit_width_of_type}>
    BitWidth {
        bit_width_of_type: NonZeroU8,
        bit_width_of_value: NonZeroU8,
    },
    /// negative value out of range for UInt<{bit_width_of_type}>
    Negative { bit_width_of_type: NonZeroU8 },
}

impl OutOfRange {
    #[cold]
    fn bit_width<const BITWIDTH: usize>(bit_width: u32) -> Self {
        Self::BitWidth {
            bit_width_of_type: u8::try_from(BITWIDTH)
                .expect("valid bit widths always fit in u8")
                .try_into()
                .expect("we don't use 0-width integers"),
            bit_width_of_value: u8::try_from(bit_width)
                .expect("valid bit widths always fit in u8")
                .try_into()
                .expect("0 fits in any width integer"),
        }
    }

    #[cold]
    fn negative<const BITWIDTH: usize>() -> Self {
        Self::Negative {
            bit_width_of_type: u8::try_from(BITWIDTH)
                .expect("valid bit widths always fit in u8")
                .try_into()
                .expect("we don't use 0-width integers"),
        }
    }
}

/// A value guaranteed to be in the range `0 .. 2 ** BITWIDTH`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, derive_more::Display)]
pub struct UInt<const BITWIDTH: usize>(u64);

/// Compatible with Java `int`, Swift `UInt32`, JavaScript `number`.
pub type U31 = UInt<31>;
/// Compatible with Java `long`, Swift `UInt64`, JavaScript `number`.
///
/// See <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER>.
pub type U53 = UInt<53>;
/// Compatible with Java `long`, Swift `UInt64`, JavaScript `bigint`.
pub type U63 = UInt<63>;

impl<const BITWIDTH: usize> TryFrom<u64> for UInt<BITWIDTH> {
    type Error = OutOfRange;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        // Replace with u64::bit_width when we reach MSRV 1.97.
        let bit_width = if value == 0 { 0 } else { value.ilog2() + 1 };
        if usize::try_from(bit_width).expect("usize is bigger than u32") <= BITWIDTH {
            Ok(Self(value))
        } else {
            Err(OutOfRange::bit_width::<BITWIDTH>(bit_width))
        }
    }
}

impl<const BITWIDTH: usize> TryFrom<i64> for UInt<BITWIDTH> {
    type Error = OutOfRange;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map_err(|_| OutOfRange::negative::<BITWIDTH>())?
            .try_into()
    }
}

impl<const BITWIDTH: usize> TryFrom<u32> for UInt<BITWIDTH> {
    type Error = OutOfRange;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::try_from(u64::from(value))
    }
}

impl<const BITWIDTH: usize> TryFrom<i32> for UInt<BITWIDTH> {
    type Error = OutOfRange;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map_err(|_| OutOfRange::negative::<BITWIDTH>())?
            .try_into()
    }
}

impl<const BITWIDTH: usize> From<UInt<BITWIDTH>> for u64 {
    fn from(value: UInt<BITWIDTH>) -> Self {
        const {
            assert!(BITWIDTH <= 64, "this type doesn't support larger bitwidths");
        }
        value.0
    }
}

impl<const BITWIDTH: usize> From<UInt<BITWIDTH>> for i64 {
    fn from(value: UInt<BITWIDTH>) -> Self {
        const {
            assert!(BITWIDTH < 64, "this type doesn't support larger bitwidths");
        }
        value.0.try_into().expect("validated on construction")
    }
}

impl<const BITWIDTH: usize> From<UInt<BITWIDTH>> for u32
where
    typenum::Const<BITWIDTH>:
        typenum::ToUInt<Output: typenum::IsLessOrEqual<typenum::U32, Output = typenum::True>>,
{
    fn from(value: UInt<BITWIDTH>) -> Self {
        value.0.try_into().expect("validated on construction")
    }
}

impl<const BITWIDTH: usize> From<UInt<BITWIDTH>> for i32
where
    typenum::Const<BITWIDTH>:
        typenum::ToUInt<Output: typenum::IsLess<typenum::U32, Output = typenum::True>>,
{
    fn from(value: UInt<BITWIDTH>) -> Self {
        value.0.try_into().expect("validated on construction")
    }
}

/// See <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER>.
impl<const BITWIDTH: usize> From<UInt<BITWIDTH>> for f64
where
    typenum::Const<BITWIDTH>:
        typenum::ToUInt<Output: typenum::IsLessOrEqual<typenum::U53, Output = typenum::True>>,
{
    fn from(value: UInt<BITWIDTH>) -> Self {
        value.0 as f64
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn round_trip() {
        assert_eq!(u64::from(U53::try_from(12345u64).expect("in range")), 12345);
        assert_eq!(i64::from(U53::try_from(12345i64).expect("in range")), 12345);
        assert_eq!(
            f64::from(U53::try_from(12345i64).expect("in range")),
            12345.0
        );

        assert_eq!(u32::from(U31::try_from(12345u32).expect("in range")), 12345);
        assert_eq!(i32::from(U31::try_from(12345i32).expect("in range")), 12345);
    }

    #[test]
    fn out_of_range() {
        assert_matches!(U53::try_from(1u64 << 53), Err(_));
        assert_matches!(U53::try_from(u64::MAX), Err(_));
        assert_matches!(U53::try_from(-1i64), Err(_));
        assert_matches!(U53::try_from(i64::MAX), Err(_));
        assert_matches!(U53::try_from(i64::MIN), Err(_));
        assert_matches!(U53::try_from(-1i32), Err(_));
        assert_matches!(U53::try_from(i32::MIN), Err(_));

        assert_matches!(U31::try_from(u32::MAX), Err(_));
        assert_matches!(U31::try_from(u64::MAX), Err(_));
        assert_matches!(U31::try_from(-1i64), Err(_));
        assert_matches!(U31::try_from(i64::MAX), Err(_));
        assert_matches!(U31::try_from(i64::MIN), Err(_));
        assert_matches!(U31::try_from(-1i32), Err(_));
        assert_matches!(U31::try_from(i32::MIN), Err(_));
    }

    #[test]
    fn display() {
        assert_eq!(U53::try_from(12345).expect("in range").to_string(), "12345");
    }
}

/// Compilation tests for [`UInt`].
///
/// First, a basic one to show the structure is working:
///
/// ```
/// use libsignal_bridge_types::support::UInt;
/// let _ = u32::from(UInt::<31>::try_from(1u32).unwrap());
/// let _ = i32::from(UInt::<31>::try_from(1u32).unwrap());
/// let _ = f64::from(UInt::<31>::try_from(1u32).unwrap());
/// ```
///
/// Then examples that should fail:
///
/// ```compile_fail
/// use libsignal_bridge_types::support::UInt;
/// let _ = u32::from(UInt::<48>::try_from(1u32).unwrap());
/// ```
///
/// ```compile_fail
/// use libsignal_bridge_types::support::UInt;
/// let _ = i32::from(UInt::<48>::try_from(1u32).unwrap());
/// ```
///
/// ```compile_fail
/// use libsignal_bridge_types::support::UInt;
/// let _ = f64::from(UInt::<56>::try_from(1u32).unwrap());
/// ```
#[cfg(doctest)]
fn bitwidth_limits_available_from_impls() {}
