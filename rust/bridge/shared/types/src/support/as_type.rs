//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

/// A wrapper type that indicates that `T` should be converted to/from `P`
/// across the bridge.
///
/// This should not be used to convert user-provided data since the error messages are not very friendly. A failure to
/// convert from `P` to `T` indicates a bug in libsignal or in application code.
#[derive(derive_more::Deref)]
pub struct AsType<T, P, const LABEL: u128 = 0> {
    #[deref]
    stored: T,
    bridged: PhantomData<P>,
}

impl<T, P, const LABEL: u128> AsType<T, P, LABEL> {
    pub fn into_inner(self) -> T {
        self.stored
    }
}

impl<T, P, const LABEL: u128> From<T> for AsType<T, P, LABEL> {
    fn from(value: T) -> Self {
        Self {
            stored: value,
            bridged: PhantomData,
        }
    }
}

/// Embeds the bytes of `input` (which must be ASCII) in a `u128` for use in const generics.
pub const fn str_as_int(input: &str) -> u128 {
    assert!(input.len() <= std::mem::size_of::<u128>(), "too long");
    assert!(input.is_ascii(), "can't deal with multibyte characters");
    let mut bytes = [0; std::mem::size_of::<u128>()];
    // Use a big-endian representation, so that printing the number as hex already puts the
    // characters in the right order.
    let str_as_bytes = input.as_bytes();
    bytes
        .split_at_mut(std::mem::size_of::<u128>() - str_as_bytes.len())
        .1
        .copy_from_slice(str_as_bytes);
    u128::from_be_bytes(bytes)
}

/// Wrapper type used to reverse the effects of `str_as_int`.
pub struct DisplayIntLabel(pub u128);
impl std::fmt::Display for DisplayIntLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0.to_be_bytes();
        let start = bytes.iter().position(|x| *x != 0).unwrap_or(bytes.len());
        bytes[start..].escape_ascii().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use super::*;

    #[test_matrix(["", "label", "0123456789abcdef"])]
    fn round_trip_label(label: &str) {
        assert_eq!(label, DisplayIntLabel(str_as_int(label)).to_string());
    }

    #[test]
    fn zero_label_is_empty() {
        static_assertions::const_assert_eq!(0, str_as_int(""));
        assert_eq!("", DisplayIntLabel(0).to_string());
    }

    #[test]
    fn labels_use_big_endian_hex_for_debugging() {
        // If we used little-endian encoding, we'd get "dcba";
        // if we used big-endian encoding aligned to the wrong end of the buffer, we'd get "abcd\0\0\0\0…".
        assert_eq!(hex::encode("abcd"), format!("{:x}", str_as_int("abcd")));
    }
}

/// Compilation tests for [`str_as_int`].
///
/// First, a basic one to show the structure is working:
///
/// ```
/// use libsignal_bridge_types::support::str_as_int;
/// const EXAMPLE: u128 = str_as_int("0123456789abcdef");
/// ```
///
/// Then examples that should fail:
///
/// ```compile_fail
/// use libsignal_bridge_types::support::str_as_int;
/// const EXAMPLE: u128 = str_as_int("0123456789abcdef_");
/// ```
#[cfg(doctest)]
fn overlong_label_const_panics() {}
