//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fs::File;

use arrayvec::ArrayVec;
use futures::io::{AllowStdIo, Cursor};
use futures::AsyncRead;
use mediasan_common::{AsyncSkip, SeekSkipAdapter};

/// Provider of an [`AsyncRead`] and [`AsyncSkip`] reader.
pub trait ReaderFactory {
    /// The reader type being created
    type Reader: AsyncRead + AsyncSkip;

    /// Creates a new reader.
    fn make_reader(&mut self) -> futures::io::Result<Self::Reader>;
}

/// Implementation of [`ReaderFactory`] that opens the same file path.
#[derive(Debug)]
pub struct FileReaderFactory<P> {
    pub path: P,
}

/// Implementation of [`ReaderFactory`] that produces cursors into a buffer.
#[derive(Debug)]
pub struct CursorFactory<B>(B);

impl<B> CursorFactory<B> {
    pub fn new(buffer: B) -> Self {
        Self(buffer)
    }
}

/// Implementation of [`ReaderFactory`] with a pre-allocated set of readers.
pub struct LimitedReaderFactory<R, const N: usize>(ArrayVec<R, N>);

impl<R, const N: usize> LimitedReaderFactory<R, N> {
    pub fn new(mut readers: [R; N]) -> Self {
        // Reverse the list so we can return streams by popping from the back.
        readers.reverse();
        Self(readers.into())
    }
}

impl<P: AsRef<std::path::Path>> ReaderFactory for FileReaderFactory<P> {
    type Reader = SeekSkipAdapter<AllowStdIo<File>>;

    fn make_reader(&mut self) -> futures::io::Result<Self::Reader> {
        File::open(&self.path)
            .map(AllowStdIo::new)
            .map(SeekSkipAdapter)
    }
}

impl<'a, B: AsRef<[u8]> + ?Sized> ReaderFactory for CursorFactory<&'a B> {
    type Reader = Cursor<&'a B>;

    fn make_reader(&mut self) -> futures::io::Result<Self::Reader> {
        Ok(Cursor::new(self.0))
    }
}

impl<R: AsyncRead + AsyncSkip, const N: usize> ReaderFactory for LimitedReaderFactory<R, N> {
    type Reader = R;

    fn make_reader(&mut self) -> futures::io::Result<Self::Reader> {
        self.0.pop().ok_or_else(|| {
            futures::io::Error::new(
                futures::io::ErrorKind::Other,
                "pre-allocated streams exhausted",
            )
        })
    }
}
