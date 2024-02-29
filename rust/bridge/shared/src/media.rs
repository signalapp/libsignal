//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use signal_media::sanitize::mp4::SanitizedMetadata;
use signal_media::sanitize::{mp4, webp};

use crate::io::{AsyncInput, InputStream, SyncInput, SyncInputStream};

// Not used by the Java bridge.
#[allow(unused_imports)]
use crate::support::*;
use crate::*;

// Will be unused when building for Node only.
#[allow(unused_imports)]
use futures_util::FutureExt;

/// Exposed so that we have an easy method to invoke from Java to test whether libsignal was
/// compiled with signal-media.
#[bridge_fn]
fn SignalMedia_CheckAvailable() {}

#[bridge_fn]
async fn Mp4Sanitizer_Sanitize(
    input: &mut dyn InputStream,
    len: u64,
) -> Result<SanitizedMetadata, mp4::Error> {
    let input = AsyncInput::new(input, len);
    let metadata = mp4::sanitize(input).await?;
    Ok(metadata)
}

#[bridge_fn]
fn WebpSanitizer_Sanitize(input: &mut dyn SyncInputStream) -> Result<(), webp::Error> {
    let input = SyncInput::new(input, None);
    webp::sanitize(input)?;
    Ok(())
}

bridge_handle!(SanitizedMetadata);

#[bridge_fn]
fn SanitizedMetadata_GetMetadata(sanitized: &SanitizedMetadata) -> &[u8] {
    sanitized.metadata.as_deref().unwrap_or_default()
}

#[bridge_fn]
fn SanitizedMetadata_GetDataOffset(sanitized: &SanitizedMetadata) -> u64 {
    sanitized.data.offset
}

#[bridge_fn]
fn SanitizedMetadata_GetDataLen(sanitized: &SanitizedMetadata) -> u64 {
    sanitized.data.len
}
