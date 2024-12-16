//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Signal remote message backup utilities.
//!
//! Contains code to read and validate message backup files.

// There are feature guards being produced as the result of a bug in the
// array-concat crate. Silence the warnings for them since they're otherwise
// harmless. See https://github.com/inspier/array-concat/issues/3.
#![cfg_attr(test, allow(unexpected_cfgs))]

use std::time::Duration;

use futures::AsyncRead;
use mediasan_common::AsyncSkip;
use protobuf::Message as _;

use crate::backup::method::{Store, ValidateOnly};
use crate::backup::{CompletedBackup, Purpose};
use crate::frame::{
    HmacMismatchError, ReaderFactory, UnvalidatedHmacReader, VerifyHmac, VerifyHmacError,
};
use crate::key::MessageBackupKey;
use crate::parse::VarintDelimitedReader;
use crate::unknown::{FormatPath, PathPart, UnknownValue, VisitUnknownFieldsExt as _};

pub mod args;
pub mod backup;
pub mod frame;
pub mod key;
pub mod parse;
pub mod unknown;

// visibility::make isn't supported for modules, so we have to write it twice instead.
#[cfg(feature = "test-util")]
pub mod proto;
#[cfg(not(feature = "test-util"))]
pub(crate) mod proto;

#[cfg(feature = "test-util")]
pub mod export;

#[cfg(feature = "scramble")]
pub mod scramble;

pub struct BackupReader<R> {
    purpose: Purpose,
    reader: VarintDelimitedReader<R>,
    pub visitor: fn(&dyn std::fmt::Debug),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// {0}
    BackupValidation(#[from] backup::ValidationError),
    /// {0}
    BackupCompletion(#[from] backup::CompletionError),
    /// {0}
    Parse(#[from] parse::ParseError),
    /// no frames found
    NoFrames,
    /// invalid protobuf: {0}
    InvalidProtobuf(#[from] protobuf::Error),
    /// mismatched HMAC: {0}
    HmacMismatch(#[from] HmacMismatchError),
}

#[must_use]
pub struct ReadResult<B> {
    pub result: Result<B, Error>,
    pub found_unknown_fields: Vec<FoundUnknownField>,
}

#[derive(Debug, thiserror::Error)]
#[must_use]
pub struct ReadError {
    pub error: Error,
    pub found_unknown_fields: Vec<FoundUnknownField>,
}

impl ReadError {
    /// Creates a `ReadError` without including any unknown field info.
    ///
    /// Not a `From` implementation to remind callers not to *discard* unknown field info they may
    /// have.
    pub fn with_error_only(error: Error) -> Self {
        Self {
            error,
            found_unknown_fields: vec![],
        }
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            error,
            found_unknown_fields,
        } = self;
        write!(f, "{error} (with ")?;
        if found_unknown_fields.is_empty() {
            write!(f, "no unknown fields")?;
        } else {
            write!(f, "unknown fields: ")?;
            f.debug_list().entries(found_unknown_fields).finish()?;
        }
        write!(f, ")")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoundUnknownField {
    pub frame_index: usize,
    pub path: Vec<PathPart>,
    pub value: UnknownValue,
}

impl std::fmt::Display for FoundUnknownField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            frame_index,
            path,
            value,
        } = self;
        write!(
            f,
            "in frame {frame_index}, {} has unknown {}",
            FormatPath(path.as_slice()),
            value
        )
    }
}

impl<R> ReadResult<R> {
    fn and_then<T>(self, f: impl FnOnce(R) -> Result<T, Error>) -> ReadResult<T> {
        let Self {
            result,
            found_unknown_fields,
        } = self;
        ReadResult {
            found_unknown_fields,
            result: result.and_then(f),
        }
    }
}

impl<R: AsyncRead + Unpin + VerifyHmac> BackupReader<R> {
    pub async fn read_all(self) -> ReadResult<backup::CompletedBackup<Store>> {
        self.collect_all()
            .await
            .and_then(|r| Ok(CompletedBackup::try_from(r)?))
    }

    pub async fn validate_all(self) -> ReadResult<()> {
        self.collect_all().await.and_then(|partial| {
            let _: CompletedBackup<ValidateOnly> = partial.try_into()?;
            Ok(())
        })
    }

    pub async fn collect_all<M: backup::method::Method + backup::ReferencedTypes>(
        self,
    ) -> ReadResult<backup::PartialBackup<M>>
    where
        backup::PartialBackup<M>: Send,
    {
        let Self {
            reader,
            visitor,
            purpose,
        } = self;

        let mut found_unknown_fields = Vec::new();
        let result = read_all_frames(purpose, reader, visitor, &mut found_unknown_fields).await;
        ReadResult {
            found_unknown_fields,
            result,
        }
    }
}

impl<R: AsyncRead + Unpin> BackupReader<UnvalidatedHmacReader<R>> {
    pub fn new_unencrypted(reader: R, purpose: Purpose) -> Self {
        let reader = VarintDelimitedReader::new(UnvalidatedHmacReader::new(reader));
        Self {
            reader,
            purpose,
            visitor: |_| (),
        }
    }
}

impl<R: AsyncRead + AsyncSkip + Unpin> BackupReader<frame::FramesReader<R>> {
    pub async fn new_encrypted_compressed(
        key: &MessageBackupKey,
        factory: impl ReaderFactory<Reader = R>,
        purpose: Purpose,
    ) -> Result<Self, frame::ValidationError> {
        let reader = frame::FramesReader::new(key, factory).await?;
        Ok(Self {
            reader: VarintDelimitedReader::new(reader),
            purpose,
            visitor: |_| (),
        })
    }
}

async fn read_all_frames<M: backup::method::Method + backup::ReferencedTypes>(
    purpose: Purpose,
    mut reader: VarintDelimitedReader<impl AsyncRead + Unpin + VerifyHmac>,
    mut visitor: impl FnMut(&dyn std::fmt::Debug) + Send + 'static,
    unknown_fields: &mut Vec<FoundUnknownField>,
) -> Result<backup::PartialBackup<M>, Error>
where
    backup::PartialBackup<M>: Send,
{
    let add_found_unknown =
        |unknown_fields: &mut Vec<FoundUnknownField>, found_unknown: Vec<_>, index| {
            let iter = found_unknown
                .into_iter()
                .map(|(path, value)| FoundUnknownField {
                    frame_index: index,
                    path,
                    value,
                });
            unknown_fields.extend(iter);
        };

    let first = reader.read_next().await?.ok_or(Error::NoFrames)?;
    let backup_info = proto::backup::BackupInfo::parse_from_bytes(&first)?;

    visitor(&backup_info);
    add_found_unknown(unknown_fields, backup_info.collect_unknown_fields(), 0);

    let mut backup = backup::PartialBackup::new(backup_info, purpose)?;

    // From here on we split the work into two separate threads:
    // - this thread, which reads frames from the reader
    // - the "frame-processing thread", which parses and validates frames
    // Processing frames is faster than reading them, so the channel between threads shouldn't fill
    // up, but just in case there's a bound on the channel for the processing thread to apply
    // backpressure. Why not split the pipeline more evenly? Above VarintDelimitedReader, we have a
    // bytestream; only below it do we have data divided into chunks *known* to correspond to units
    // of work.
    const FRAMES_IN_FLIGHT: usize = 20;
    let (frame_tx, frame_rx) = std::sync::mpsc::sync_channel::<Box<[u8]>>(FRAMES_IN_FLIGHT);

    let frame_processing_thread = std::thread::Builder::new()
        .name("libsignal-backup-processing".to_owned())
        .spawn(move || {
            let mut unknown_fields = vec![];
            let mut frame_index = 1;

            // Continue until all frames have been read from the stream...
            loop {
                let frame = loop {
                    match frame_rx.try_recv() {
                        Ok(frame) => break frame,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            // ...as signalled by the sender being dropped.
                            return Ok::<_, Error>((backup, unknown_fields));
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            // Rather than doing a blocking read, just sleep quickly to let the
                            // other side catch up. This turns out to be faster than waiting for a
                            // proper wake from the reader side, at the cost of a bit of CPU.
                            // Yielding rather than sleeping *does* make the process even faster,
                            // but there's a possibility of getting in a hot spin loop.
                            std::thread::sleep(Duration::from_nanos(100));
                        }
                    }
                };

                let these_unknown_fields =
                    backup.parse_and_add_frame(&frame, |frame| visitor(frame))?;
                add_found_unknown(&mut unknown_fields, these_unknown_fields, frame_index);
                frame_index += 1;
            }
        })
        .expect("can create threads");

    'outer: while let Some(mut buf) = reader.read_next().await? {
        // Try to send to the processing thread in a spin-loop.
        // Normally the processing thread is faster than the reader thread, so this should only spin
        // a few times before success, which is faster than going to sleep and waiting to be woken.
        loop {
            buf = match frame_tx.try_send(buf) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    // If the frame-processing thread ends early, there must have been an error in
                    // an earlier frame. In that case, no point in continuing to read.
                    break 'outer;
                }
                Err(std::sync::mpsc::TrySendError::Full(buf)) => {
                    std::thread::yield_now();
                    buf
                }
            }
        }
    }
    // Let the frame-processing thread know there's nothing more to read.
    drop(frame_tx);

    let (backup, inner_unknown_fields) = match frame_processing_thread.join() {
        Ok(Ok(success)) => success,
        Ok(Err(validation_error)) => return Err(validation_error),
        Err(panic) => std::panic::resume_unwind(panic),
    };
    unknown_fields.extend(inner_unknown_fields);

    // Before reporting success, check that the HMAC still matches. This
    // prevents TOC/TOU issues.
    reader.into_inner().verify_hmac().await?;

    Ok(backup)
}

impl<M: backup::method::Method + backup::ReferencedTypes> backup::PartialBackup<M> {
    pub fn by_parsing(
        raw_backup_info: &[u8],
        purpose: Purpose,
        mut visitor: impl FnMut(&proto::backup::BackupInfo) + Send,
    ) -> Result<Self, crate::Error> {
        let backup_info_proto = proto::backup::BackupInfo::parse_from_bytes(raw_backup_info)?;
        visitor(&backup_info_proto);
        for (path, value) in backup_info_proto.collect_unknown_fields() {
            // This API doesn't have a good way to report unknown fields; logging is the best we can
            // do if we don't want a fatal error.
            log::warn!(
                "BackupInfo proto: {}",
                FoundUnknownField {
                    frame_index: 0,
                    path,
                    value
                }
            );
        }
        Ok(Self::new(backup_info_proto, purpose)?)
    }

    pub fn parse_and_add_frame(
        &mut self,
        raw_frame: &[u8],
        mut visitor: impl FnMut(&proto::backup::Frame) + Send,
    ) -> Result<Vec<(Vec<PathPart>, UnknownValue)>, crate::Error> {
        // Using `merge_from_bytes` instead of `parse_from_bytes` avoids having to unpack the Ok
        // case of the Result. (This is guaranteed equivalent by protobuf.)
        let mut frame_proto = proto::backup::Frame::new();
        frame_proto.merge_from_bytes(raw_frame)?;
        visitor(&frame_proto);
        let unknown_fields = frame_proto.collect_unknown_fields();
        self.add_frame(frame_proto)?;
        Ok(unknown_fields)
    }
}

impl From<VerifyHmacError> for Error {
    fn from(value: VerifyHmacError) -> Self {
        match value {
            VerifyHmacError::HmacMismatch(e) => e.into(),
            VerifyHmacError::Io(e) => Self::Parse(e.into()),
        }
    }
}

/// Rounds `content_length` up to obscure the exact size of a backup.
pub fn padded_length(content_length: u32) -> u32 {
    const BASE: f64 = 1.05;
    let exp = f64::log(content_length.into(), BASE).ceil();

    #[allow(clippy::cast_possible_truncation)]
    {
        u32::max(541, BASE.powf(exp).floor() as u32)
    }
}
