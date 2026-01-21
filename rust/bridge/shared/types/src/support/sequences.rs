//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use libsignal_protocol::{ServiceId, ServiceIdFixedWidthBinaryBytes};
use rayon::iter::ParallelIterator as _;

use crate::*;

/// Lazily parses ServiceIds from a buffer of concatenated Service-Id-FixedWidthBinary.
///
/// **Reports parse errors by panicking.** All errors represent mistakes on the app side of the
/// bridge, though; a buffer that really is constructed from concatenating service IDs should never
/// error.
#[derive(Clone, Copy, Debug)]
pub struct ServiceIdSequence<'a>(&'a [u8]);

impl<'a> ServiceIdSequence<'a> {
    const SERVICE_ID_FIXED_WIDTH_BINARY_LEN: usize =
        std::mem::size_of::<ServiceIdFixedWidthBinaryBytes>();

    pub fn parse(input: &'a [u8]) -> Self {
        let extra_bytes = input.len() % Self::SERVICE_ID_FIXED_WIDTH_BINARY_LEN;
        assert!(
            extra_bytes == 0,
            concat!(
                "input should be a concatenated list of Service-Id-FixedWidthBinary, ",
                "but has length {} ({} extra bytes)"
            ),
            input.len(),
            extra_bytes
        );
        Self(input)
    }

    fn parse_single_chunk(chunk: &ServiceIdFixedWidthBinaryBytes) -> ServiceId {
        ServiceId::parse_from_service_id_fixed_width_binary(chunk).expect(concat!(
            "input should be a concatenated list of Service-Id-FixedWidthBinary, ",
            "but one ServiceId was invalid"
        ))
    }
}

impl<'a> IntoIterator for ServiceIdSequence<'a> {
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, [u8; 17]>,
        for<'b> fn(&'b ServiceIdFixedWidthBinaryBytes) -> ServiceId,
    >;
    type Item = ServiceId;

    fn into_iter(self) -> Self::IntoIter {
        self.0.as_chunks().0.iter().map(Self::parse_single_chunk)
    }
}

impl<'a> rayon::iter::IntoParallelIterator for ServiceIdSequence<'a> {
    type Iter = rayon::iter::Map<
        rayon::slice::Iter<'a, ServiceIdFixedWidthBinaryBytes>,
        for<'b> fn(&'b ServiceIdFixedWidthBinaryBytes) -> ServiceId,
    >;
    type Item = ServiceId;

    fn into_par_iter(self) -> Self::Iter {
        self.0
            .as_chunks()
            .0
            .into_par_iter()
            .map(Self::parse_single_chunk)
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct BridgedStringMap(HashMap<String, Arc<str>>);

impl BridgedStringMap {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub fn take(&mut self) -> HashMap<String, Arc<str>> {
        std::mem::take(&mut self.0)
    }
}

impl Deref for BridgedStringMap {
    type Target = HashMap<String, Arc<str>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for BridgedStringMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl From<BridgedStringMap> for HashMap<String, Arc<str>> {
    fn from(value: BridgedStringMap) -> Self {
        value.0
    }
}

bridge_as_handle!(BridgedStringMap, mut = true);
