//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::process::ExitCode;

use clap::Parser;
use clap_stdin::FileOrStdin;
use futures::future::Either;
use libsignal_message_backup::backup::{CompletedBackup, PartialBackup, Purpose, ValidateOnly};
use libsignal_message_backup::frame::{FramesReader, ReaderFactory as _};
use libsignal_message_backup::parse::VarintDelimitedReader;
use libsignal_message_backup::scramble::Scrambler;
use libsignal_message_backup::unknown::VisitUnknownFieldsExt as _;
use libsignal_message_backup::FoundUnknownField;

#[path = "../src/bin/support/mod.rs"]
mod support;
use support::{AsyncReaderFactory, FilenameOrContents, KeyArgs};

#[derive(Parser)]
/// Replaces the most obvious identifying information in an backup.
///
/// The backup will still be identifiable in practice (e.g. from its timestamps), but all text,
/// names, ACIs, etc will be scrambled. The output (on stdout) is unencrypted binproto.
struct CliArgs {
    /// the file to read from, or '-' to read from stdin
    #[arg(value_hint = clap::ValueHint::FilePath)]
    input: FileOrStdin,

    /// the purpose the backup is intended for, used to check that validation results haven't
    /// changed
    #[arg(long, default_value_t=Purpose::RemoteBackup)]
    purpose: Purpose,

    #[command(flatten)]
    key_args: KeyArgs,
}

fn main() -> ExitCode {
    // We don't enable warnings from the main validator by default, because we don't want the
    // scrambler's warnings to be drowned out.
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Error)
        .filter_module(module_path!(), log::LevelFilter::Info)
        .parse_default_env()
        .init();
    let CliArgs {
        input,
        purpose,
        key_args,
    } = CliArgs::parse();

    let source = input.filename().to_owned();
    let contents = FilenameOrContents::from(input);
    let mut factory = AsyncReaderFactory::from(&contents);

    futures::executor::block_on(async move {
        let reader = if let Some(key) = key_args.into_key() {
            log::info!("reading from {source:?}");
            Either::Left(
                FramesReader::new(&key, factory)
                    .await
                    .expect("can read from input"),
            )
        } else {
            log::info!("reading from UNENCRYPTED {source:?}");
            Either::Right(factory.make_reader().expect("can read from input"))
        };

        let mut reader = VarintDelimitedReader::new(reader);
        let mut scrambler = Scrambler::new();
        let mut exit_code = ExitCode::SUCCESS;

        let raw_backup_info = reader
            .read_next()
            .await
            .expect("can read from input")
            .expect("has backup info");
        let mut new_backup_info = None;
        let mut original_backup =
            PartialBackup::<ValidateOnly>::by_parsing(&raw_backup_info, purpose, |info| {
                new_backup_info = Some(scrambler.scramble(info))
            })
            .expect("valid BackupInfo, at least");
        let new_backup_info = new_backup_info.expect("processed successfully");
        emit_proto(&new_backup_info);
        let mut new_backup = PartialBackup::<ValidateOnly>::new_validator(new_backup_info, purpose)
            .expect("original backup only fails if new backup does");

        let mut frame_index = 0;
        while let Some(raw_frame) = reader.read_next().await.expect("can read from input") {
            let mut new_frame = None;
            let original_result = original_backup.parse_and_add_frame(&raw_frame, |frame| {
                new_frame = Some(scrambler.scramble(frame))
            });
            frame_index += 1;

            match &original_result {
                Ok(unknown_fields) => {
                    for (path, value) in unknown_fields {
                        log::warn!(
                            "{}",
                            FoundUnknownField {
                                frame_index,
                                path: path.clone(),
                                value: *value,
                            }
                        );
                    }
                }
                Err(e) => {
                    log::warn!("frame {frame_index} did not validate: {e}");
                }
            }

            let Some(new_frame) = new_frame else { continue };
            let new_unknown_fields = new_frame.collect_unknown_fields();
            emit_proto(&new_frame);
            let new_result = new_backup.add_frame(new_frame);

            match (original_result, new_result) {
                (Ok(original_unknown_fields), Ok(())) => {
                    if original_unknown_fields.len() != new_unknown_fields.len() {
                        log::warn!("scrambling may have removed some unknown fields in frame {frame_index}; here are the post-scrambling fields:");
                        for (path, value) in new_unknown_fields {
                            log::info!(
                                "{}",
                                FoundUnknownField {
                                    frame_index,
                                    path: path.clone(),
                                    value,
                                }
                            );
                        }
                    }
                }
                (Ok(_), Err(e)) => {
                    log::error!("scrambling of frame {frame_index} introduced a new error: {e} (continuing anyway!)");
                    exit_code = ExitCode::FAILURE;
                }
                (Err(old_error), Err(new_error)) => {
                    if old_error.to_string() != new_error.to_string() {
                        log::warn!("validation error for frame {frame_index} changed post-scrambling: {new_error}");
                    }
                }
                (Err(_), Ok(_)) => {
                    log::error!("scrambling of frame {frame_index} removed an error; this may no longer be a suitable test case!");
                    exit_code = ExitCode::FAILURE;
                }
            }
        }

        log::info!("processed {frame_index} frames");

        match (
            CompletedBackup::try_from(original_backup),
            CompletedBackup::try_from(new_backup),
        ) {
            (Ok(_), Ok(_)) => {}
            (Ok(_), Err(e)) => {
                log::error!("scrambling introduced a new error: {e}");
                exit_code = ExitCode::FAILURE;
            }
            (Err(old_error), Err(new_error)) => {
                log::warn!("full backup failed to validate: {old_error}");
                if old_error.to_string() != new_error.to_string() {
                    log::warn!("validation error changed post-scrambling: {new_error}");
                }
            }
            (Err(old_error), Ok(_)) => {
                log::warn!("full backup failed to validate: {old_error}");
                log::error!(
                    "scrambling removed an error; this may no longer be a suitable test case!"
                );
                exit_code = ExitCode::FAILURE;
            }
        }

        exit_code
    })
}

fn emit_proto(message: &impl protobuf::Message) {
    message
        .write_length_delimited_to_writer(&mut std::io::stdout())
        .expect("can write to stdout");
}
