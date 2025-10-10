//
// Copyright (C) 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{self, ErrorKind};

use futures::future::FutureExt;
use futures::io::Cursor;
use serde::Serialize;
use serde_json::ser::PrettyFormatter;
use serde_json::{Serializer, Value as JsonValue};

use crate::backup::{self, Purpose};
use crate::parse::VarintDelimitedReader;
use crate::{Error, ReadError};

/// Streaming exporter that converts backups into pretty-printed JSON arrays.
pub struct JsonExporter {
    validator: Option<backup::PartialBackup<backup::ValidateOnly>>,
}

impl JsonExporter {
    /// Creates a new exporter and returns the initial JSON chunk containing the backup info.
    pub fn new(backup_info: &[u8], should_validate: bool) -> Result<(Self, String), ReadError> {
        let validator = if should_validate {
            Some(
                backup::PartialBackup::by_parsing(
                    backup_info,
                    Purpose::TakeoutExport,
                    |_| {}, // No need to inspect BackupInfo proto during export
                )
                .map_err(ReadError::with_error_only)?,
            )
        } else {
            None
        };

        let json = parse_backup_info_json(backup_info)?;

        let mut output = String::from("[\n");
        render_pretty_json_list_items(std::iter::once(&json), &mut output)?;

        Ok((Self { validator }, output))
    }

    /// Converts a batch of frames into a JSON chunk.
    pub fn export_frames(&mut self, frames: &[u8]) -> Result<String, ReadError> {
        validate_frames_if_requested(self.validator.as_mut(), frames)?;

        let values =
            backup::frames_to_json_values(frames).map_err(convert_to_json_error_to_read_error)?;

        if values.is_empty() {
            return Ok(String::new());
        }

        let mut chunk = String::from(",\n");
        render_pretty_json_list_items(values.iter(), &mut chunk)?;

        Ok(chunk)
    }

    /// Finalizes the exporter and returns the closing JSON chunk.
    pub fn finish(&mut self) -> Result<String, ReadError> {
        if let Some(validator) = self.validator.take() {
            backup::CompletedBackup::try_from(validator)
                .map_err(|error| ReadError::with_error_only(error.into()))?;
        }

        Ok(String::from("\n]\n"))
    }
}

fn convert_to_json_error_to_read_error(error: backup::ConvertToJsonError) -> ReadError {
    match error {
        backup::ConvertToJsonError::ProtoEncode(err) => {
            ReadError::with_error_only(Error::InvalidProtobuf(err))
        }
        backup::ConvertToJsonError::Io(err) => ReadError::with_error_only(Error::Parse(err)),
        backup::ConvertToJsonError::ProtoJsonPrint(err) => ReadError::with_error_only(
            Error::Parse(io::Error::new(ErrorKind::InvalidData, err.to_string())),
        ),
        backup::ConvertToJsonError::Json(err) => ReadError::with_error_only(Error::Parse(
            io::Error::new(ErrorKind::InvalidData, err.to_string()),
        )),
    }
}

fn parse_backup_info_json(bytes: &[u8]) -> Result<JsonValue, ReadError> {
    backup::backup_info_to_json_value(bytes).map_err(convert_to_json_error_to_read_error)
}

fn render_pretty_json(value: &JsonValue) -> Result<String, ReadError> {
    let mut buffer = Vec::new();
    let formatter = PrettyFormatter::with_indent(b"  ");
    let mut serializer = Serializer::with_formatter(&mut buffer, formatter);

    value.serialize(&mut serializer).map_err(|err| {
        ReadError::with_error_only(Error::Parse(io::Error::new(
            ErrorKind::InvalidData,
            err.to_string(),
        )))
    })?;

    String::from_utf8(buffer).map_err(|err| {
        ReadError::with_error_only(Error::Parse(io::Error::new(
            ErrorKind::InvalidData,
            err.to_string(),
        )))
    })
}

// PrettyFormatter handles relative indentation but not the initial offset inside the streaming
// output. We copy each formatted line into the destination buffer with the desired base indent so
// callers only allocate their final chunk once.
fn render_pretty_json_list_items<'a>(
    items: impl IntoIterator<Item = &'a JsonValue>,
    dest: &mut String,
) -> Result<(), ReadError> {
    const BASE_INDENT: &str = "  ";

    for (idx, value) in items.into_iter().enumerate() {
        if idx > 0 {
            dest.push_str(",\n");
        }

        let pretty = render_pretty_json(value)?;
        for (line_idx, line) in pretty.lines().enumerate() {
            if line_idx > 0 {
                dest.push('\n');
            }
            dest.push_str(BASE_INDENT);
            dest.push_str(line);
        }
    }

    Ok(())
}

fn validate_frames_if_requested(
    validator: Option<&mut backup::PartialBackup<backup::ValidateOnly>>,
    frames: &[u8],
) -> Result<(), ReadError> {
    let Some(validator) = validator else {
        return Ok(());
    };

    let mut reader = VarintDelimitedReader::new(Cursor::new(frames));

    async {
        while let Some(frame) = reader
            .read_next()
            .await
            .map_err(|err| ReadError::with_error_only(Error::Parse(err)))?
        {
            validator
                .parse_and_add_frame(
                    &frame,
                    |_| {}, // No need to inspect Frame proto during export
                )
                .map_err(ReadError::with_error_only)?;
        }

        Ok(())
    }
    .now_or_never()
    .expect("cursor never yields")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use protobuf::{CodedInputStream, Message as _};
    use serde_json::json;

    use super::*;
    use crate::proto::backup as proto;

    fn sample_backup_info_bytes() -> Vec<u8> {
        let mut info = proto::BackupInfo::new();
        info.version = 1;
        info.backupTimeMs = 1;
        info.mediaRootBackupKey = vec![0; libsignal_account_keys::BACKUP_KEY_LEN];
        info.currentAppVersion = "1.0.0".into();
        info.firstAppVersion = "1.0.0".into();
        info.debugInfo = b"debug".to_vec();

        info.write_to_bytes().expect("can serialize backup info")
    }

    fn encode_frame(frame: proto::Frame) -> Vec<u8> {
        let mut bytes = Vec::new();
        frame
            .write_length_delimited_to_vec(&mut bytes)
            .expect("can serialize frame");
        bytes
    }

    #[test]
    fn export_frames_returns_empty_chunk_for_no_frames() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        let chunk = exporter
            .export_frames(&[])
            .expect("exporting empty frames succeeds");

        assert!(chunk.is_empty());
    }

    #[test]
    fn export_frames_formats_frame_boundaries_correctly() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        let frame = proto::Frame::new();
        let frames = encode_frame(frame);

        let chunk = exporter
            .export_frames(&frames)
            .expect("exporting simple frame succeeds");

        assert!(chunk.starts_with(",\n  {"));
        assert!(chunk.ends_with('}'));
    }

    #[test]
    fn finish_returns_closing_chunk_without_validation() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        let chunk = exporter.finish().expect("finish succeeds");
        assert_eq!(chunk, "\n]\n");
    }

    #[test]
    fn finish_reports_validation_error_when_enabled() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), true).expect("should succeed");

        let err = exporter
            .finish()
            .expect_err("validation should fail without frames");

        assert!(
            matches!(err.error, Error::BackupCompletion(_)) || matches!(err.error, Error::NoFrames)
        );
    }

    #[test]
    fn render_pretty_json_list_items_indents_values() {
        let values = [json!({"a": 1}), json!({"b": 2})];
        let mut output = String::new();
        render_pretty_json_list_items(values.iter(), &mut output).expect("format succeeds");

        let expected = "  {
    \"a\": 1
  },
  {
    \"b\": 2
  }";
        assert_eq!(output, expected);
    }

    #[test]
    fn exporter_matches_known_output() {
        let binproto = include_bytes!("../../tests/res/canonical-backup.binproto");

        // This is the same dependency VarintDelimitedReader uses to split the backup, just
        // called directly for this test only to provide the smallest amount of insurance
        // against bugs in our VarintDelimitedReader implementation.
        let mut stream = CodedInputStream::from_bytes(binproto);
        let info_len: usize = stream
            .read_raw_varint32()
            .expect("backup info length varint")
            .try_into()
            .expect("fits in usize");
        let header_len: usize = stream.pos().try_into().expect("fits in usize");
        let info_end = header_len + info_len;
        let (backup_info, frames) = (&binproto[header_len..info_end], &binproto[info_end..]);

        let (mut exporter, mut combined_output) =
            JsonExporter::new(backup_info, true).expect("exporter initialization succeeds");
        if !frames.is_empty() {
            combined_output.push_str(
                &exporter
                    .export_frames(frames)
                    .expect("frame export succeeds"),
            );
        }
        combined_output.push_str(&exporter.finish().expect("finish succeeds"));

        let expected_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/res/canonical-backup.takeout-export.expected.json");

        if write_expected_output() {
            eprintln!("writing expected exporter output to {expected_path:?}");
            std::fs::write(&expected_path, &combined_output)
                .expect("failed to overwrite expected contents");
            return;
        }

        let expected = std::fs::read_to_string(&expected_path)
            .expect("failed to load expected exporter output");

        pretty_assertions::assert_str_eq!(expected, combined_output);
    }

    fn write_expected_output() -> bool {
        std::env::var_os("OVERWRITE_EXPECTED_OUTPUT").is_some()
    }
}
