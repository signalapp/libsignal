//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

mod address;
// Not exporting the members because they have overly-generic names.
pub mod curve;
mod e164;
mod version;

pub use address::{
    Aci, DeviceId, InvalidDeviceId, Pni, ProtocolAddress, ServiceId,
    ServiceIdFixedWidthBinaryBytes, ServiceIdKind, WrongKindOfServiceIdError,
};
pub use e164::E164;
pub use version::VERSION;

/// Simple wrapper that invokes a lambda.
///
/// Once try-blocks are stabilized
/// (<https://github.com/rust-lang/rust/issues/31436>), usages of this function
/// can be removed and replaced with the new syntax.
#[inline]
#[track_caller]
pub fn try_scoped<T, E>(f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    f()
}

/// Produces three arrays of output based on a callback that fills a single buffer of bytes.
///
/// The length of the buffer will always be `N1 + N2 + N3` (it would be possible to guarantee this
/// using `generic_array`, but the added complexity doesn't actually buy us anything). If you don't
/// need all three arrays, you can pattern-match the last one as `[]` to both discard it and infer
/// its length as 0.
#[inline]
pub fn derive_arrays<const N1: usize, const N2: usize, const N3: usize>(
    derive: impl FnOnce(&mut [u8]),
) -> ([u8; N1], [u8; N2], [u8; N3]) {
    let Ok(result) = try_derive_arrays::<N1, N2, N3, std::convert::Infallible>(move |buffer| {
        derive(buffer);
        Ok(())
    });
    result
}

/// Like [`derive_arrays`], but the callback is permitted to fail.
#[inline]
#[allow(clippy::type_complexity)]
pub fn try_derive_arrays<const N1: usize, const N2: usize, const N3: usize, E>(
    derive: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> Result<([u8; N1], [u8; N2], [u8; N3]), E> {
    #[derive(zerocopy::KnownLayout, zerocopy::FromBytes, zerocopy::IntoBytes)]
    #[repr(C)]
    struct DerivedValues<const N1: usize, const N2: usize, const N3: usize>(
        [u8; N1],
        [u8; N2],
        [u8; N3],
    );
    let mut derived_values: DerivedValues<N1, N2, N3> = zerocopy::FromZeros::new_zeroed();
    derive(zerocopy::IntoBytes::as_mut_bytes(&mut derived_values))?;
    Ok((derived_values.0, derived_values.1, derived_values.2))
}
