//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;

use futures_util::AsyncRead;

/// The maximum size of metadata to support, setting an upper bound on memory consumption in the parser.
const MAX_METADATA_SIZE: u64 = 300 * 1024 * 1024;

pub use mp4san::parse::ParseError;
pub use mp4san::{AsyncSkip, InputSpan, SanitizedMetadata};

/// Error type returned by [`sanitize_mp4`].
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// An IO error while reading the media.
    #[error("{0}")]
    Io(IoError),

    /// An error parsing the media stream.
    #[error("{0}")]
    Parse(ParseErrorReport),
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("IO error: {kind}: {message}")]
/// A decomposed and stringified [`io::Error'].
pub struct IoError {
    pub kind: io::ErrorKind,
    pub message: String,
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("Parse error: {kind}\n{report}")]
/// A decomposed and stringified [`error_stack::Report<ParseError>`](mp4san::Error::Parse).
pub struct ParseErrorReport {
    /// The specific kind of parse error.
    pub kind: ParseError,

    /// A developer-readable parser stack trace.
    pub report: String,
}

/// Sanitize an MP4 input.
///
/// The input must implement [`AsyncRead`] + [`AsyncSkip`], where `AsyncSkip` represents a subset of the [`AsyncSeek`]
/// trait; an input stream which can be skipped forward, but not necessarily seeked to arbitrary positions.
///
/// # Errors
///
/// If the input cannot be parsed, or an IO error occurs, an `Error` is returned.
pub async fn sanitize_mp4<R: AsyncRead + AsyncSkip>(input: R) -> Result<SanitizedMetadata, Error> {
    let config = mp4san::Config::builder()
        .max_metadata_size(MAX_METADATA_SIZE)
        .build();
    let metadata = mp4san::sanitize_async_with_config(input, config).await?;
    Ok(metadata)
}

impl From<mp4san::Error> for Error {
    fn from(from: mp4san::Error) -> Self {
        match from {
            mp4san::Error::Io(err) => Self::Io(IoError {
                kind: err.kind(),
                message: err
                    .into_inner()
                    .map(|err| format!("{err:?}"))
                    .unwrap_or_default(),
            }),
            mp4san::Error::Parse(err) => Self::Parse(ParseErrorReport {
                kind: err.get_ref().clone(),
                report: format!("{err:?}"),
            }),
        }
    }
}

impl From<IoError> for io::Error {
    fn from(from: IoError) -> Self {
        io::Error::new(from.kind, from.message)
    }
}
