//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Signal remote message backup utilities.
//!
use futures::AsyncRead;
use mediasan_common::AsyncSkip;
use protobuf::Message as _;

use crate::frame::ReaderFactory;
use crate::key::MessageBackupKey;
use crate::parse::VarintDelimitedReader;
use crate::unknown::{FormatPath, PathPart, UnknownValue, VisitUnknownFieldsExt as _};

pub mod args;
pub mod backup;
pub mod frame;
pub mod key;
pub mod parse;
pub mod unknown;

#[cfg(not(feature = "expose-proto-types"))]
pub(crate) mod proto;
#[cfg(feature = "expose-proto-types")]
pub mod proto;

pub struct BackupReader<R> {
    reader: VarintDelimitedReader<R>,
    pub visitor: fn(&dyn std::fmt::Debug),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// {0}
    BackupValidation(#[from] backup::ValidationError),
    /// {0}
    Parse(#[from] parse::ParseError),
    /// no frames found
    NoFrames,
    /// invalid protobuf: {0}
    InvalidProtobuf(#[from] protobuf::Error),
}

#[must_use]
pub struct ReadResult<B> {
    pub result: Result<B, Error>,
    pub found_unknown_fields: Vec<FoundUnknownField>,
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
    fn map<T>(self, f: impl FnOnce(R) -> T) -> ReadResult<T> {
        let Self {
            result,
            found_unknown_fields,
        } = self;
        ReadResult {
            found_unknown_fields,
            result: result.map(f),
        }
    }
}

impl<R: AsyncRead + Unpin> BackupReader<R> {
    pub fn new_unencrypted(reader: R) -> Self {
        let reader = VarintDelimitedReader::new(reader);
        Self {
            reader,
            visitor: |_| (),
        }
    }

    pub async fn read_all(self) -> ReadResult<backup::Backup> {
        self.collect_all().await.map(Into::into)
    }

    pub async fn validate_all(self) -> ReadResult<()> {
        self.collect_all()
            .await
            .map(|_: backup::PartialBackup<backup::method::ValidateOnly>| ())
    }

    pub async fn collect_all<M: backup::method::Method>(
        self,
    ) -> ReadResult<backup::PartialBackup<M>> {
        let Self { reader, visitor } = self;

        let mut found_unknown_fields = Vec::new();
        let result = read_all_frames(reader, visitor, &mut found_unknown_fields).await;
        ReadResult {
            found_unknown_fields,
            result,
        }
    }
}

impl<R: AsyncRead + AsyncSkip + Unpin> BackupReader<frame::FramesReader<R>> {
    pub async fn new_encrypted_compressed(
        key: &MessageBackupKey,
        factory: impl ReaderFactory<Reader = R>,
    ) -> Result<Self, frame::ValidationError> {
        let reader = frame::FramesReader::new(key, factory).await?;
        Ok(Self::new_unencrypted(reader))
    }
}

async fn read_all_frames<M: backup::method::Method>(
    mut reader: VarintDelimitedReader<impl AsyncRead + Unpin>,
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

    let mut backup = backup::PartialBackup::new(backup_info);
    let mut frame_index = 1;

    while let Some(frame) = reader.read_next().await? {
        let frame_proto = proto::backup::Frame::parse_from_bytes(&frame)?;
        visitor(&frame_proto);
        add_found_unknown(frame_proto.collect_unknown_fields(), frame_index);
        frame_index += 1;

        backup.add_frame(frame_proto)?
    }

    Ok(backup)
}
