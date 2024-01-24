//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Read as _;

use clap::{Args, Parser};
use futures::io::{AllowStdIo, Cursor};
use futures::AsyncRead;

use libsignal_message_backup::args::{parse_aci, parse_hex_bytes};
use libsignal_message_backup::frame::FramesReader;
use libsignal_message_backup::key::{BackupKey, MessageBackupKey};
use libsignal_message_backup::unknown::FormatPath;
use libsignal_message_backup::{BackupReader, Error, FoundUnknownField, ReadResult};
use libsignal_protocol::Aci;

use crate::args::ParseVerbosity;

mod args;

/// Validates, and optionally prints the contents of, message backup files.
///
/// Backups can be read from a file or from stdin. If no keys are provided, the
/// backup is assumed to be a sequence of varint-delimited protos. Otherwise,
/// the backup file is assumed to be an encrypted gzip-compressed sequence of
/// followed by an HMAC of the contents.
#[derive(Debug, Parser)]
struct Cli {
    /// filename to read the backup from, or - for stdin
    #[arg(value_hint = clap::ValueHint::FilePath)]
    file: clap_stdin::FileOrStdin,

    /// causes additional output to be printed to stderr; passing the flag multiple times increases the verbosity
    #[arg(short='v', action=clap::ArgAction::Count)]
    verbose: u8,

    /// when set, the validated backup contents are printed to stdout
    #[arg(long)]
    print: bool,

    // TODO once https://github.com/clap-rs/clap/issues/5292 is resolved, make
    // `derive_key` and `key_parts` Optional at the top level.
    #[command(flatten)]
    derive_key: DeriveKey,

    #[command(flatten)]
    key_parts: KeyParts,
}

#[derive(Debug, Args, PartialEq)]
#[group(conflicts_with = "KeyParts")]
struct DeriveKey {
    /// account master key, used with the ACI to derive the message backup key
    #[arg(long, value_parser=parse_hex_bytes::<32>, requires="aci")]
    master_key: Option<[u8; BackupKey::MASTER_KEY_LEN]>,
    /// ACI for the backup creator
    #[arg(long, value_parser=parse_aci, requires="master_key")]
    aci: Option<Aci>,
}

#[derive(Debug, Args, PartialEq)]
#[group(conflicts_with = "DeriveKey")]
struct KeyParts {
    /// HMAC key, used if the master key is not provided
    #[arg(long, value_parser=parse_hex_bytes::<32>, requires_all=["aes_key", "iv"])]
    hmac_key: Option<[u8; MessageBackupKey::HMAC_KEY_LEN]>,
    /// AES encryption key, used if the master key is not provided
    #[arg(long, value_parser=parse_hex_bytes::<32>, requires_all=["hmac_key", "iv"])]
    aes_key: Option<[u8; MessageBackupKey::AES_KEY_LEN]>,
    /// AES IV bytes, used if the master key is not provided
    #[arg(long, value_parser=parse_hex_bytes::<16>, requires_all=["hmac_key", "aes_key"])]
    iv: Option<[u8; MessageBackupKey::IV_LEN]>,
}

fn main() {
    futures::executor::block_on(async_main())
}

async fn async_main() {
    let Cli {
        file: file_or_stdin,

        derive_key,

        key_parts,

        print,
        verbose,
    } = Cli::parse();
    let print = PrintOutput(print);

    let verbosity = verbose.into();

    let derive_key = {
        let DeriveKey { master_key, aci } = derive_key;
        master_key.zip(aci)
    };
    let key_parts = {
        let KeyParts {
            hmac_key,
            aes_key,
            iv,
        } = key_parts;
        hmac_key.zip(aes_key).zip(iv)
    };

    let key = {
        match (derive_key, key_parts) {
            (None, None) => None,
            (None, Some(((hmac_key, aes_key), iv))) => Some(MessageBackupKey {
                aes_key,
                hmac_key,
                iv,
            }),
            (Some((master_key, aci)), None) => Some({
                let backup_key = BackupKey::derive_from_master_key(&master_key);
                let backup_id = backup_key.derive_backup_id(&aci);
                MessageBackupKey::derive(&backup_key, &backup_id)
            }),
            (Some(_), Some(_)) => unreachable!("disallowed by clap arg parser"),
        }
    };

    let input = into_async_reader(file_or_stdin);

    let reader = if let Some(key) = key {
        MaybeEncryptedBackupReader::EncryptedCompressed(Box::new(
            BackupReader::new_encrypted_compressed(&key, input)
                .await
                .unwrap_or_else(|e| panic!("invalid encrypted backup: {e:#}")),
        ))
    } else {
        MaybeEncryptedBackupReader::PlaintextBinproto(BackupReader::new_unencrypted(input))
    };

    reader
        .execute(print, verbosity)
        .await
        .unwrap_or_else(|e| panic!("backup error: {e:#}"));
}

/// [`AsyncRead`] & [`futures::AsyncSeek`] impl backed by a file or in-memory
/// buffer.
type AsyncReader = futures::future::Either<
    // Using `AllowStdIo` with a `File` isn't generally a good idea since
    // the `Read` implementation will block. Since we're using a
    // single-threaded executor, though, the blocking I/O isn't a problem.
    // If that changes, this should be changed to an async-aware type, like
    // something from the `tokio` or `async-std` crates.
    AllowStdIo<std::fs::File>,
    Cursor<Box<[u8]>>,
>;

fn into_async_reader(arg: clap_stdin::FileOrStdin) -> AsyncReader {
    match arg.source {
        clap_stdin::Source::Stdin => {
            let mut buffer = vec![];
            std::io::stdin()
                .lock()
                .read_to_end(&mut buffer)
                .expect("failed to read from stdin");
            AsyncReader::Right(Cursor::new(buffer.into_boxed_slice()))
        }
        clap_stdin::Source::Arg(path) => AsyncReader::Left(AllowStdIo::new(
            std::fs::File::open(path).expect("failed to open file"),
        )),
    }
}

/// Wrapper over encrypted- or plaintext-sourced [`BackupReader`].
enum MaybeEncryptedBackupReader<R: AsyncRead + Unpin> {
    EncryptedCompressed(Box<BackupReader<FramesReader<R>>>),
    PlaintextBinproto(BackupReader<R>),
}

struct PrintOutput(bool);

impl<R: AsyncRead + Unpin> MaybeEncryptedBackupReader<R> {
    async fn execute(self, print: PrintOutput, verbosity: ParseVerbosity) -> Result<(), Error> {
        async fn validate(
            mut backup_reader: BackupReader<impl AsyncRead + Unpin>,
            PrintOutput(print): PrintOutput,
            verbosity: ParseVerbosity,
        ) -> Result<(), Error> {
            if let Some(visitor) = verbosity.into_visitor() {
                backup_reader.visitor = visitor;
            }
            let ReadResult {
                found_unknown_fields,
                result,
            } = backup_reader.read_all().await;

            print_unknown_fields(found_unknown_fields);
            let backup = result?;

            if print {
                println!("{backup:#?}");
            }
            Ok(())
        }

        match self {
            Self::EncryptedCompressed(reader) => validate(*reader, print, verbosity).await,
            Self::PlaintextBinproto(reader) => validate(reader, print, verbosity).await,
        }
    }
}

fn print_unknown_fields(found_unknown_fields: Vec<FoundUnknownField>) {
    if found_unknown_fields.is_empty() {
        return;
    }

    eprintln!("not all proto values were recognized; found the following unknown values:");
    for FoundUnknownField {
        frame_index,
        path,
        value,
    } in found_unknown_fields
    {
        eprintln!(
            "in frame {frame_index}, {} has unknown {}",
            FormatPath(path),
            value
        );
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use clap_stdin::FileOrStdin;

    use super::*;

    const EXECUTABLE_NAME: &str = "validate_bin";

    #[test]
    fn cli_parse_empty() {
        let e = assert_matches!(Cli::try_parse_from([EXECUTABLE_NAME]), Err(e) => e);
        assert_eq!(e.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        assert!(e.to_string().contains("<FILE>"), "{e}");
    }

    #[test]
    fn cli_parse_no_keys_plaintext_binproto() {
        const INPUT: &[&str] = &[EXECUTABLE_NAME, "filename"];

        let file_source = assert_matches!(Cli::try_parse_from(INPUT), Ok(Cli {
            file:
                FileOrStdin {
                    source: clap_stdin::Source::Arg(file_source),
                    ..
                },
            verbose: 0,
            print: false,
            derive_key: DeriveKey { master_key: None, aci: None},
            key_parts: KeyParts { hmac_key: None, aes_key: None, iv: None },
        }) =>  file_source);
        assert_eq!(file_source, "filename");
    }

    #[test]
    fn cli_parse_derive_keys() {
        const INPUT: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--master-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--aci",
            "55555555-5555-5555-5555-555555555555",
        ];

        let (file_source, derive_key) = assert_matches!(Cli::try_parse_from(INPUT), Ok(Cli {
            file:
                FileOrStdin {
                    source: clap_stdin::Source::Arg(file_source),
                    ..
                },
            verbose: 0,
            print: false,
            derive_key,
            key_parts: KeyParts { hmac_key: None, aes_key: None, iv: None },
        }) => (file_source, derive_key));
        assert_eq!(file_source, "filename");
        assert_eq!(
            derive_key,
            DeriveKey {
                master_key: Some([0xaa; 32]),
                aci: Some(Aci::from_uuid_bytes([0x55; 16]))
            }
        );
    }

    #[test]
    fn cli_parse_key_parts() {
        const INPUT: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--hmac-key",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--aes-key",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "--iv",
            "dddddddddddddddddddddddddddddddd",
        ];

        let (file_source, key_parts) = assert_matches!(Cli::try_parse_from(INPUT), Ok(Cli {
            file:
                FileOrStdin {
                    source: clap_stdin::Source::Arg(file_source),
                    ..
                },
            verbose: 0,
            print: false,
            derive_key: DeriveKey { master_key: None, aci: None},
            key_parts,
        }) => (file_source, key_parts));
        assert_eq!(file_source, "filename");
        assert_eq!(
            key_parts,
            KeyParts {
                aes_key: Some([0xcc; 32]),
                hmac_key: Some([0xbb; 32]),
                iv: Some([0xdd; 16]),
            }
        );
    }

    #[test]
    fn cli_parse_master_key_requires_aci() {
        const INPUT: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--master-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        let e = assert_matches!(Cli::try_parse_from(INPUT), Err(e) => e);
        assert_eq!(e.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        assert!(e.to_string().contains("--aci <ACI>"), "{e}");
    }

    #[test]
    fn cli_parse_key_parts_all_required() {
        const INPUT: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--hmac-key",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--aes-key",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ];
        let e = assert_matches!(Cli::try_parse_from(INPUT), Err(e) => e);
        assert_eq!(e.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        assert!(e.to_string().contains("--iv <IV>"), "{e}");
    }

    #[test]
    fn cli_parse_derive_key_flags_conflict_with_key_parts_flags() {
        const INPUT_PREFIX: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--master-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--aci",
            "55555555-5555-5555-5555-555555555555",
        ];
        const CONFLICTING_FLAGS: [&[&str]; 3] = [
            &[
                "--hmac-key",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
            &[
                "--aes-key",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
            &["--iv", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        ];
        for case in CONFLICTING_FLAGS {
            println!("case: {case:?}");
            let e =
                assert_matches!(Cli::try_parse_from(INPUT_PREFIX.iter().chain(case)), Err(e) => e);
            assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict);

            assert!(e.to_string().contains("--aci <ACI>"), "{e}");
        }
    }
}
