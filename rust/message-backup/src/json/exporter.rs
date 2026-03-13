//
// Copyright (C) 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{self, ErrorKind};

use futures::executor::block_on;
use futures::io::Cursor;
use itertools::Itertools as _;
use protobuf::Message as _;

use crate::backup::{self, Purpose};
use crate::parse::VarintDelimitedReader;
use crate::proto::backup as proto;
use crate::{Error, FoundUnknownField};

/// Streaming exporter that converts backups into newline-delimited JSON objects.
pub struct JsonExporter {
    validator: Option<backup::PartialBackup<backup::ValidateOnly>>,
}

#[derive(Debug)]
pub struct FrameExportResult {
    pub line: Option<String>,
    pub validation_error: Option<Error>,
}

impl JsonExporter {
    /// Creates a new exporter and returns the initial JSON line containing the backup info.
    pub fn new(backup_info: &[u8], should_validate: bool) -> Result<(Self, String), Error> {
        let validator = if should_validate {
            Some(backup::PartialBackup::by_parsing(
                backup_info,
                Purpose::TakeoutExport,
                |_| {}, // No need to inspect BackupInfo proto during export
            )?)
        } else {
            None
        };

        let line = parse_backup_info_json(backup_info)?;
        Ok((Self { validator }, line))
    }

    /// Converts a batch of frames into JSON lines.
    ///
    /// If rendering or semantic validation fails for a frame, the corresponding result contains
    /// the rendered line if available alongside the error instead of aborting the entire batch.
    pub fn export_frames(&mut self, frames: &[u8]) -> Result<Vec<FrameExportResult>, Error> {
        let mut reader = VarintDelimitedReader::new(Cursor::new(frames));
        let validator = &mut self.validator;

        block_on(async {
            let mut results = Vec::new();

            while let Some(frame) = reader.read_next().await.map_err(Error::Parse)? {
                let proto_frame =
                    proto::Frame::parse_from_bytes(&frame).map_err(Error::InvalidProtobuf)?;

                let frame_index = results.len();
                let (sanitized_bytes, line, render_error) = match sanitize_frame(proto_frame) {
                    Some(frame) => {
                        let sanitized_bytes =
                            frame.write_to_bytes().map_err(Error::InvalidProtobuf)?;

                        // Rendering to JSON can fail on frames that are still valid enough to
                        // be safely sanitized and checked with the validator (e.g. a frame with
                        // an unknown enum value), so treat render errors as per-frame rather than
                        // aborting the whole export.
                        let (line, render_error) =
                            match backup::frame_to_json_string(&sanitized_bytes) {
                                Ok(line) => (Some(line), None),
                                Err(error) => (
                                    None,
                                    Some(frame_render_error(
                                        frame_index,
                                        convert_to_json_error_to_lib_error(error),
                                    )),
                                ),
                            };

                        (Some(sanitized_bytes), line, render_error)
                    }
                    None => (None, None, None),
                };

                let validation_error = match (validator.as_mut(), sanitized_bytes) {
                    (Some(validator), Some(sanitized_bytes)) => {
                        match validator.parse_and_add_frame(&sanitized_bytes, |_| {}) {
                            Ok(unknown_fields) if unknown_fields.is_empty() => None,
                            Ok(unknown_fields) => {
                                // Since our export is already "best-effort", we allow unknown fields to
                                // appear in the exported data, but synthesize an error message for
                                // them.
                                Some(Error::Parse(io::Error::other(
                                    unknown_fields
                                        .into_iter()
                                        .map(FoundUnknownField::in_frame(results.len()))
                                        .join("; "),
                                )))
                            }
                            Err(error) => Some(error),
                        }
                    }
                    (_, _) => None,
                };

                results.push(FrameExportResult {
                    line,
                    validation_error: combine_frame_errors(render_error, validation_error),
                });
            }

            Ok(results)
        })
    }

    /// Finalizes the exporter, surfacing any trailing semantic validation errors.
    pub fn finish(&mut self) -> Result<(), Error> {
        if let Some(validator) = self.validator.take() {
            backup::CompletedBackup::try_from(validator)?;
        }

        Ok(())
    }
}

fn convert_to_json_error_to_lib_error(error: backup::ConvertToJsonError) -> Error {
    match error {
        backup::ConvertToJsonError::ProtoDecode(err) => {
            Error::InvalidProtobuf(protobuf::Error::from(std::io::Error::from(err)))
        }
        backup::ConvertToJsonError::Io(err) => Error::Parse(err),
        backup::ConvertToJsonError::Json(err) => {
            Error::Parse(io::Error::new(ErrorKind::InvalidData, err.to_string()))
        }
    }
}

fn frame_render_error(frame_index: usize, error: Error) -> Error {
    Error::Parse(io::Error::new(
        ErrorKind::InvalidData,
        format!("in frame {frame_index}, failed to render JSON: {error}"),
    ))
}

fn combine_frame_errors(
    render_error: Option<Error>,
    validation_error: Option<Error>,
) -> Option<Error> {
    match (render_error, validation_error) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(render_error), Some(validation_error)) => Some(Error::Parse(io::Error::other(
            format!("{render_error}; {validation_error}"),
        ))),
    }
}

fn parse_backup_info_json(bytes: &[u8]) -> Result<String, Error> {
    backup::backup_info_to_json_string(bytes).map_err(convert_to_json_error_to_lib_error)
}

fn sanitize_frame(mut frame: proto::Frame) -> Option<proto::Frame> {
    match frame.item.take() {
        Some(proto::frame::Item::ChatItem(chat_item)) => {
            sanitize_chat_item(chat_item).map(|sanitized_chat_item| {
                frame.item = Some(proto::frame::Item::ChatItem(sanitized_chat_item));
                frame
            })
        }
        Some(item) => {
            frame.item = Some(item);
            Some(frame)
        }
        None => Some(frame),
    }
}

fn sanitize_chat_item(mut chat_item: proto::ChatItem) -> Option<proto::ChatItem> {
    if chat_item.expiresInMs.is_some() {
        return None;
    }

    if let Some(proto::chat_item::Item::ViewOnceMessage(view_once)) = chat_item.item.as_mut() {
        view_once.attachment.clear();
    }

    let sanitized_revisions: Vec<_> = chat_item
        .revisions
        .into_iter()
        .filter_map(sanitize_chat_item)
        .collect();
    chat_item.revisions = sanitized_revisions;

    Some(chat_item)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;
    use protobuf::{CodedInputStream, Message as _, MessageField};

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

        let results = exporter
            .export_frames(&[])
            .expect("exporting empty frames succeeds");

        assert!(results.is_empty());
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

        assert_eq!(chunk.len(), 1, "expected a single JSON line");
        assert!(chunk[0].validation_error.is_none());
        let line = chunk[0].line.as_ref().expect("line should be present");
        serde_json::from_str::<serde_json::Value>(line)
            .expect("line should parse as JSON")
            .as_object()
            .expect("expected frame JSON to be an object");
    }

    #[test]
    fn export_frames_handles_disappearing_messages() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        let mut chat_item = proto::ChatItem::new();
        chat_item.chatId = 1;
        chat_item.authorId = 2;
        chat_item.dateSent = 3;
        chat_item.expiresInMs = Some(1);

        let mut frame = proto::Frame::new();
        frame.item = Some(proto::frame::Item::ChatItem(chat_item));

        let frames = encode_frame(frame);
        let chunk = exporter
            .export_frames(&frames)
            .expect("exporting frames succeeds");

        assert_matches!(
            chunk[..],
            [FrameExportResult {
                line: None,
                validation_error: None
            }],
            "disappearing message should be filtered"
        );
    }

    #[test]
    fn export_frames_reports_validation_error_for_filtered_frame() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), true).expect("should succeed");

        let mut chat_item = proto::ChatItem::new();
        chat_item.chatId = 42;
        chat_item.authorId = 1;
        chat_item.dateSent = 2;
        chat_item.expiresInMs = Some(3);

        let mut frame = proto::Frame::new();
        frame.item = Some(proto::frame::Item::ChatItem(chat_item));

        let frames = encode_frame(frame);
        let chunk = exporter
            .export_frames(&frames)
            .expect("exporting frames succeeds");

        assert_eq!(chunk.len(), 1, "filtered frame should still yield a result");
        let result = &chunk[0];
        assert!(
            result.line.is_none(),
            "filtered frame should not render JSON output"
        );
        assert!(
            result.validation_error.is_none(),
            "there should be no validation error from the filtered frame, because the sanitizer ran on it before validation"
        );
    }

    #[test]
    fn export_frames_strips_view_once_attachment() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        let mut attachment = proto::MessageAttachment::new();
        attachment.wasDownloaded = true;

        let mut view_once = proto::ViewOnceMessage::new();
        view_once.attachment = MessageField::some(attachment);

        let mut chat_item = proto::ChatItem::new();
        chat_item.chatId = 1;
        chat_item.authorId = 2;
        chat_item.dateSent = 3;
        chat_item.item = Some(proto::chat_item::Item::ViewOnceMessage(view_once));

        let mut frame = proto::Frame::new();
        frame.item = Some(proto::frame::Item::ChatItem(chat_item));

        let frames = encode_frame(frame);
        let chunk = exporter
            .export_frames(&frames)
            .expect("exporting frames succeeds");

        assert_eq!(chunk.len(), 1);
        let line = chunk[0].line.as_ref().expect("line should be present");
        let json: serde_json::Value =
            serde_json::from_str(line).expect("line should parse as JSON");
        let view_once_json = json
            .get("chatItem")
            .and_then(|chat_item| chat_item.get("viewOnceMessage"))
            .expect("view once message present");
        assert!(
            view_once_json.get("attachment").is_none(),
            "attachment should be removed"
        );
    }

    #[test]
    fn export_frames_filters_disappearing_revisions() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        let mut revision = proto::ChatItem::new();
        revision.chatId = 1;
        revision.authorId = 2;
        revision.dateSent = 4;
        revision.expiresInMs = Some(5);

        let mut chat_item = proto::ChatItem::new();
        chat_item.chatId = 1;
        chat_item.authorId = 2;
        chat_item.dateSent = 3;
        chat_item.revisions.push(revision);

        let mut frame = proto::Frame::new();
        frame.item = Some(proto::frame::Item::ChatItem(chat_item));

        let frames = encode_frame(frame);
        let chunk = exporter
            .export_frames(&frames)
            .expect("exporting frames succeeds");

        assert_eq!(chunk.len(), 1);
        let line = chunk[0].line.as_ref().expect("line should be present");
        let json: serde_json::Value =
            serde_json::from_str(line).expect("line should parse as JSON");
        let revisions = json
            .get("chatItem")
            .and_then(|chat_item| chat_item.get("revisions"));
        assert!(
            revisions
                .and_then(serde_json::Value::as_array)
                .is_none_or(|array| array.is_empty()),
            "filtered revisions should not be present"
        );
    }

    #[test]
    fn export_frames_with_unknown_fields() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), true).expect("should succeed");

        let call_link = proto::CallLink::test_data();
        // Our previous library, protobuf-json-mapping, allowed this by printing the integer rather
        // than the enum's name. However, our current one, pbjson, errors out. This is not an
        // important use case for us at this time, but here's how we would test it if we switch
        // libraries again.
        //
        // call_link.restrictions = protobuf::EnumOrUnknown::from_i32(50);

        let mut recipient = proto::Recipient::new();
        recipient.id = 10;
        recipient.set_callLink(call_link);
        recipient
            .mut_unknown_fields()
            .add_length_delimited(60, b"unknown".to_vec());

        let mut frame = proto::Frame::new();
        frame.set_recipient(recipient);

        let frames = encode_frame(frame);
        let chunk = exporter
            .export_frames(&frames)
            .expect("exporting frames succeeds");

        assert_eq!(chunk.len(), 1);
        let FrameExportResult {
            line,
            validation_error,
        } = &chunk[0];
        assert_eq!(
            line.as_deref().unwrap(),
            concat!(
                r#"{"recipient":{"#,
                r#""id":"10","#,
                r#""callLink":{"#,
                r#""rootKey":"UlJSUlJSUlJSUlJSUlJSUg==","#,
                r#""adminKey":"QQ==","#,
                r#""restrictions":"NONE","#,
                r#""expirationMs":"1702944000000""#,
                r#"}}}"# // Note no representation at all of the top-level unknown field (not ideal, but reasonable).
            )
        );
        let io_error = assert_matches!(validation_error, Some(Error::Parse(e)) => e);
        assert_eq!(
            io_error.to_string(),
            "in frame 0, item.recipient has unknown field with tag 60"
        );
    }

    #[test]
    fn export_frames_reports_rendering_error_without_aborting_batch() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        let mut call_link = proto::CallLink::test_data();
        call_link.restrictions = protobuf::EnumOrUnknown::from_i32(50);

        let mut recipient = proto::Recipient::new();
        recipient.id = 10;
        recipient.set_callLink(call_link);

        let mut invalid_frame = proto::Frame::new();
        invalid_frame.set_recipient(recipient);

        let valid_frame = proto::Frame::new();

        let mut frames = encode_frame(invalid_frame);
        frames.extend(encode_frame(valid_frame));

        let results = exporter
            .export_frames(&frames)
            .expect("render failures should stay per-frame");

        assert_eq!(results.len(), 2);

        let first_result = &results[0];
        assert!(first_result.line.is_none());
        let first_error = assert_matches!(
            first_result.validation_error.as_ref(),
            Some(Error::Parse(error)) => error
        );
        assert_eq!(
            first_error.to_string(),
            "in frame 0, failed to render JSON: Invalid variant 50"
        );

        let second_result = &results[1];
        assert!(second_result.validation_error.is_none());
        assert_eq!(second_result.line.as_deref(), Some("{}"));
    }

    #[test]
    fn finish_returns_closing_chunk_without_validation() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), false).expect("should succeed");

        exporter.finish().expect("finish succeeds");
    }

    #[test]
    fn finish_reports_validation_error_when_enabled() {
        let (mut exporter, _) =
            JsonExporter::new(&sample_backup_info_bytes(), true).expect("should succeed");

        let err = exporter
            .finish()
            .expect_err("validation should fail without frames");

        assert_matches!(err, Error::BackupCompletion(_) | Error::NoFrames);
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

        let (mut exporter, initial_line) =
            JsonExporter::new(backup_info, true).expect("exporter initialization succeeds");
        let mut combined_output = Vec::from([initial_line]);
        if !frames.is_empty() {
            let frame_results = exporter
                .export_frames(frames)
                .expect("frame export succeeds");
            combined_output.extend(frame_results.into_iter().map(|result| {
                assert!(
                    result.validation_error.is_none(),
                    "canonical backup frames should not produce validation errors"
                );
                result
                    .line
                    .expect("canonical backup frames should produce JSON lines")
            }));
        }
        exporter.finish().expect("finish succeeds");

        let expected_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/res/canonical-backup.takeout-export.expected.jsonl");

        if write_expected_output() {
            eprintln!("writing expected exporter output to {expected_path:?}");
            let joined_output = combined_output.join("\n");
            std::fs::write(&expected_path, joined_output.as_bytes())
                .expect("failed to overwrite expected contents");
            return;
        }

        let expected = std::fs::read_to_string(&expected_path)
            .expect("failed to load expected exporter output");

        let expected_lines: Vec<_> = expected.lines().map(|line| line.to_owned()).collect();
        pretty_assertions::assert_eq!(expected_lines, combined_output);
    }

    fn write_expected_output() -> bool {
        std::env::var_os("OVERWRITE_EXPECTED_OUTPUT").is_some()
    }
}
