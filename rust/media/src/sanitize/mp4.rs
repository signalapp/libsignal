//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::AsyncRead;
use mediasan_common::AsyncSkip;
use mp4san::{sanitize_async_with_config, Config};

pub use mp4san::parse::ParseError;
pub use mp4san::{InputSpan, SanitizedMetadata};

/// Error type returned by [`sanitize_mp4`].
pub type Error = super::error::SanitizerError<ParseError>;

/// A decomposed and stringified [`error_stack::Report<ParseError>`](mediasan_common::Error::Parse).
pub type ParseErrorReport = super::error::ParseErrorReport<ParseError>;

/// Sanitize an MP4 input.
///
/// The input must implement [`AsyncRead`] + [`AsyncSkip`], where `AsyncSkip` represents the
/// ability to skip forward, but not necessarily seek to arbitrary positions.
///
/// # Errors
///
/// If the input cannot be parsed, or an IO error occurs, an `Error` is returned.
pub async fn sanitize<R: AsyncRead + AsyncSkip>(input: R) -> Result<SanitizedMetadata, Error> {
    let config = Config::builder()
        .max_metadata_size(MAX_METADATA_SIZE)
        .build();
    let metadata = sanitize_async_with_config(input, config).await?;
    Ok(metadata)
}

/// The maximum size of metadata to support, setting an upper bound on memory consumption in the parser.
const MAX_METADATA_SIZE: u64 = 300 * 1024 * 1024;
