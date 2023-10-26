use std::io;

use mediasan_common::error::ReportableError;

// cbindgen does not like this being called simply `Error`.
/// Error type returned by [`sanitize_*`].
#[derive(Clone, Debug, thiserror::Error)]
pub enum SanitizerError<E> {
    /// An IO error while reading the media.
    #[error("{0}")]
    Io(IoError),

    /// An error parsing the media stream.
    #[error("{0}")]
    Parse(ParseErrorReport<E>),
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
/// A decomposed and stringified [`error_stack::Report<ParseError>`](mediasan_common::Error::Parse).
pub struct ParseErrorReport<E> {
    /// The specific kind of parse error.
    pub kind: E,

    /// A developer-readable parser stack trace.
    pub report: String,
}

impl<E: Clone + ReportableError> From<mediasan_common::Error<E>> for SanitizerError<E> {
    fn from(from: mediasan_common::Error<E>) -> Self {
        match from {
            mediasan_common::Error::Io(err) => Self::Io(IoError {
                kind: err.kind(),
                message: err
                    .into_inner()
                    .map(|err| format!("{err:?}"))
                    .unwrap_or_default(),
            }),
            mediasan_common::Error::Parse(err) => Self::Parse(ParseErrorReport {
                kind: err.get_ref().clone(),
                report: format!("{err:?}"),
            }),
        }
    }
}

impl<E> From<io::Error> for SanitizerError<E> {
    fn from(from: io::Error) -> Self {
        Self::Io(IoError {
            kind: from.kind(),
            message: from
                .into_inner()
                .map(|err| format!("{err:?}"))
                .unwrap_or_default(),
        })
    }
}

impl From<IoError> for io::Error {
    fn from(from: IoError) -> Self {
        io::Error::new(from.kind, from.message)
    }
}
