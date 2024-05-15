//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Signal remote message backup file handling.
//!
//! Contains code for encrypting, decompressing, parsing, and translating backup
//! files. The protobuf message definitions are exported by this crate but only
//! the top-level messages are referenced by name to allow building even with
//! modifications to the .proto file(s).

use crate::unknown::{FormatPath, PathPart, UnknownValue};

pub mod args;
pub mod frame;
pub mod key;
pub mod parse;
pub mod proto;
pub mod unknown;

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

#[cfg(feature = "json")]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConvertJsonError {
    /// input array was empty
    EmptyArray,
    /// failed to parse JSON as proto: {0}
    ProtoJsonParse(#[from] protobuf_json_mapping::ParseError),
    /// failed to print proto as JSON: {0}
    ProtoJsonPrint(#[from] protobuf_json_mapping::PrintError),
    /// JSON error: {0}
    Json(#[from] serde_json::Error),
    /// failed to encode/decode binary protobuf: {0}
    ProtoEncode(#[from] protobuf::Error),
    /// input/output error: {0}
    Io(#[from] std::io::Error),
}

#[cfg(feature = "json")]
impl From<crate::parse::ParseError> for ConvertJsonError {
    fn from(value: crate::parse::ParseError) -> Self {
        match value {
            crate::parse::ParseError::Decode(e) => e.into(),
            crate::parse::ParseError::Io(e) => e.into(),
        }
    }
}

#[cfg(feature = "json")]
pub fn convert_from_json(json: Vec<serde_json::Value>) -> Result<Box<[u8]>, ConvertJsonError> {
    let mut it = json.into_iter();

    let backup_info = protobuf_json_mapping::parse_from_str::<proto::backup::BackupInfo>(
        &it.next().ok_or(ConvertJsonError::EmptyArray)?.to_string(),
    )?;

    let mut serialized = Vec::new();
    protobuf::Message::write_length_delimited_to_vec(&backup_info, &mut serialized)?;

    for json_frame in it {
        let frame =
            protobuf_json_mapping::parse_from_str::<proto::backup::Frame>(&json_frame.to_string())?;

        protobuf::Message::write_length_delimited_to_vec(&frame, &mut serialized)?;
    }

    Ok(serialized.into_boxed_slice())
}

#[cfg(feature = "json")]
pub async fn convert_to_json(
    length_delimited_binproto: impl futures::AsyncRead + Unpin,
) -> Result<Vec<serde_json::Value>, ConvertJsonError> {
    fn binary_proto_to_json<M: protobuf::MessageFull>(
        binary: &[u8],
    ) -> Result<serde_json::Value, ConvertJsonError> {
        let proto = M::parse_from_bytes(binary)?;
        let json_proto = protobuf_json_mapping::print_to_string(&proto)?;
        Ok(serde_json::from_str(&json_proto)?)
    }

    let mut reader = crate::parse::VarintDelimitedReader::new(length_delimited_binproto);

    let mut array = Vec::new();
    let backup_info = reader
        .read_next()
        .await?
        .ok_or(ConvertJsonError::EmptyArray)?;
    array.push(binary_proto_to_json::<proto::backup::BackupInfo>(
        &backup_info,
    )?);

    while let Some(frame) = reader.read_next().await? {
        array.push(binary_proto_to_json::<proto::backup::Frame>(&frame)?);
    }
    Ok(array)
}
