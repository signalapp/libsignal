//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Signal remote message backup utilities.
//!
//! Contains code to read and validate message backup files.

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

pub(crate) mod proto;

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
    ) -> ReadResult<backup::PartialBackup<M>> {
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
    mut visitor: impl FnMut(&dyn std::fmt::Debug),
    unknown_fields: &mut impl Extend<FoundUnknownField>,
) -> Result<backup::PartialBackup<M>, Error> {
    let mut add_found_unknown = |found_unknown: Vec<_>, index| {
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
    add_found_unknown(backup_info.collect_unknown_fields(), 0);

    let mut backup = backup::PartialBackup::new(backup_info, purpose);
    let mut frame_index = 1;

    while let Some(frame) = reader.read_next().await? {
        let frame_proto = proto::backup::Frame::parse_from_bytes(&frame)?;
        visitor(&frame_proto);
        add_found_unknown(frame_proto.collect_unknown_fields(), frame_index);
        frame_index += 1;

        backup.add_frame(frame_proto)?
    }

    // Before reporting success, check that the HMAC still matches. This
    // prevents TOC/TOU issues.
    reader.into_inner().verify_hmac().await?;

    Ok(backup)
}

impl From<VerifyHmacError> for Error {
    fn from(value: VerifyHmacError) -> Self {
        match value {
            VerifyHmacError::HmacMismatch(e) => e.into(),
            VerifyHmacError::Io(e) => Self::Parse(e.into()),
        }
    }
}
