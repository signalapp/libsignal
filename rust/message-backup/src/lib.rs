//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Signal remote message backup utilities.
//!
use futures::{AsyncRead, AsyncSeek};
use protobuf::{Message, MessageDyn};

use crate::key::MessageBackupKey;
use crate::parse::VarintDelimitedReader;

pub mod backup;
pub mod frame;
pub mod key;
pub mod parse;
pub(crate) mod proto;

pub struct BackupReader<R> {
    reader: VarintDelimitedReader<R>,
    pub visitor: fn(&dyn MessageDyn),
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

impl<R: AsyncRead + Unpin> BackupReader<R> {
    pub fn new_unencrypted(reader: R) -> Self {
        let reader = VarintDelimitedReader::new(reader);
        Self {
            reader,
            visitor: |_| (),
        }
    }

    pub async fn read_all(self) -> Result<backup::Backup, Error> {
        self.collect_all().await.map(Into::into)
    }

    pub async fn validate_all(self) -> Result<(), Error> {
        self.collect_all()
            .await
            .map(|_: backup::PartialBackup<backup::method::ValidateOnly>| ())
    }

    async fn collect_all<M: backup::method::Method>(
        self,
    ) -> Result<backup::PartialBackup<M>, Error> {
        let Self {
            mut reader,
            visitor,
        } = self;
        let first = reader.read_next().await?.ok_or(Error::NoFrames)?;
        let backup_info = Message::parse_from_bytes(&first)?;
        visitor(&backup_info);

        let mut backup = backup::PartialBackup::new(backup_info);

        while let Some(frame) = reader.read_next().await? {
            let frame_proto = Message::parse_from_bytes(&frame)?;
            visitor(&frame_proto);
            backup.add_frame(frame_proto)?
        }

        Ok(backup)
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> BackupReader<frame::FramesReader<R>> {
    pub async fn new_encrypted_compressed(
        key: &MessageBackupKey,
        reader: R,
    ) -> Result<Self, frame::ValidationError> {
        let reader = frame::FramesReader::new(key, reader).await?;
        Ok(Self::new_unencrypted(reader))
    }
}
