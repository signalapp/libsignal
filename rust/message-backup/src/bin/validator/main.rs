//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use clap::Parser;
use futures::AsyncRead;
use libsignal_message_backup::backup::Purpose;
use libsignal_message_backup::frame::{
    FramesReader, ReaderFactory as _, UnvalidatedHmacReader, VerifyHmac,
};
use libsignal_message_backup::{BackupReader, Error, FoundUnknownField, ReadResult};

use crate::args::ParseVerbosity;

mod args;

#[path = "../support/mod.rs"]
mod support;
use support::{AsyncReaderFactory, FilenameOrContents, KeyArgs};

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

    /// the purpose the backup is intended for
    #[arg(long, default_value_t=Purpose::RemoteBackup)]
    purpose: Purpose,

    #[command(flatten)]
    key_args: KeyArgs,
}

fn main() {
    futures::executor::block_on(async_main())
}

async fn async_main() {
    let Cli {
        file: file_or_stdin,
        key_args,
        purpose,
        print,
        verbose,
    } = Cli::parse();
    env_logger::init();

    let print = PrintOutput(print);

    let verbosity = verbose.into();

    let key = key_args.into_key();

    let contents = FilenameOrContents::from(file_or_stdin);
    let mut factory = AsyncReaderFactory::from(&contents);

    let reader = if let Some(key) = key {
        MaybeEncryptedBackupReader::EncryptedCompressed(Box::new(
            BackupReader::new_encrypted_compressed(&key, factory, purpose)
                .await
                .unwrap_or_else(|e| panic!("invalid encrypted backup: {e:#}")),
        ))
    } else {
        MaybeEncryptedBackupReader::PlaintextBinproto(BackupReader::new_unencrypted(
            factory.make_reader().expect("failed to read"),
            purpose,
        ))
    };

    reader
        .execute(print, verbosity)
        .await
        .unwrap_or_else(|e| panic!("backup error: {e:#}"));
}

/// Wrapper over encrypted- or plaintext-sourced [`BackupReader`].
enum MaybeEncryptedBackupReader<R: AsyncRead + Unpin> {
    EncryptedCompressed(Box<BackupReader<FramesReader<R>>>),
    PlaintextBinproto(BackupReader<UnvalidatedHmacReader<R>>),
}

struct PrintOutput(bool);

impl<R: AsyncRead + Unpin> MaybeEncryptedBackupReader<R> {
    async fn execute(self, print: PrintOutput, verbosity: ParseVerbosity) -> Result<(), Error> {
        async fn validate(
            mut backup_reader: BackupReader<impl AsyncRead + Unpin + VerifyHmac>,
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
    for field in found_unknown_fields {
        eprintln!("{field}");
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use libsignal_core::Aci;
    use support::{DeriveKey, KeyParts};
    use test_case::test_case;

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

        let file = assert_matches!(Cli::try_parse_from(INPUT), Ok(Cli {
            file,
            verbose: 0,
            print: false,
            purpose: Purpose::RemoteBackup,
            key_args: KeyArgs {
                derive_key: DeriveKey { account_entropy: None, master_key: None, aci: None },
                key_parts: KeyParts { hmac_key: None, aes_key: None }
            },
        }) => file);
        assert_eq!(file.filename(), "filename");
    }

    #[test]
    fn cli_parse_derive_keys() {
        const INPUT: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--account-entropy",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--aci",
            "55555555-5555-5555-5555-555555555555",
        ];

        let (file, derive_key) = assert_matches!(Cli::try_parse_from(INPUT), Ok(Cli {
            file,
            verbose: 0,
            print: false,
            purpose: Purpose::RemoteBackup,
            key_args: KeyArgs {
                derive_key,
                key_parts: KeyParts { hmac_key: None, aes_key: None }
            },
        }) => (file, derive_key));
        assert_eq!(file.filename(), "filename");
        assert_eq!(
            derive_key,
            DeriveKey {
                account_entropy: Some(std::str::from_utf8(&[b'a'; 64]).expect("ascii").to_owned()),
                master_key: None,
                aci: Some(Aci::from_uuid_bytes([0x55; 16]))
            }
        );
    }

    #[test]
    fn cli_parse_derive_keys_legacy() {
        const INPUT: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--master-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--aci",
            "55555555-5555-5555-5555-555555555555",
        ];

        let (file, derive_key) = assert_matches!(Cli::try_parse_from(INPUT), Ok(Cli {
            file,
            verbose: 0,
            print: false,
            purpose: Purpose::RemoteBackup,
            key_args: KeyArgs {
                derive_key,
                key_parts: KeyParts { hmac_key: None, aes_key: None }
            },
        }) => (file, derive_key));
        assert_eq!(file.filename(), "filename");
        assert_eq!(
            derive_key,
            DeriveKey {
                account_entropy: None,
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
        ];

        let (file, key_parts) = assert_matches!(Cli::try_parse_from(INPUT), Ok(Cli {
            file,
            verbose: 0,
            print: false,
            purpose: Purpose::RemoteBackup,
            key_args: KeyArgs {
                derive_key: DeriveKey { account_entropy: None, master_key: None, aci: None},
                key_parts,
            }
        }) => (file, key_parts));
        assert_eq!(file.filename(), "filename");
        assert_eq!(
            key_parts,
            KeyParts {
                aes_key: Some([0xcc; 32]),
                hmac_key: Some([0xbb; 32]),
            }
        );
    }

    #[test]
    fn cli_parse_account_entropy_requires_aci() {
        const INPUT: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--account-entropy",
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
        ];
        let e = assert_matches!(Cli::try_parse_from(INPUT), Err(e) => e);
        assert_eq!(e.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        assert!(e.to_string().contains("--aes-key <AES_KEY>"), "{e}");
    }

    #[test]
    fn cli_parse_derive_key_flags_conflict_with_key_parts_flags() {
        const INPUT_PREFIX: &[&str] = &[
            EXECUTABLE_NAME,
            "filename",
            "--account-entropy",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--aci",
            "55555555-5555-5555-5555-555555555555",
        ];
        const CONFLICTING_FLAGS: &[&[&str]] = &[
            &[
                "--hmac-key",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
            &[
                "--aes-key",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
        ];
        for case in CONFLICTING_FLAGS {
            println!("case: {case:?}");
            let e =
                assert_matches!(Cli::try_parse_from(INPUT_PREFIX.iter().chain(*case)), Err(e) => e);
            assert_eq!(e.kind(), clap::error::ErrorKind::ArgumentConflict);

            assert!(e.to_string().contains("--aci <ACI>"), "{e}");
        }
    }

    #[test_case("backup", Purpose::RemoteBackup; "remote")]
    #[test_case("remote_backup", Purpose::RemoteBackup; "remote underscore")]
    #[test_case("remote-backup", Purpose::RemoteBackup; "remote hyphen")]
    #[test_case("transfer", Purpose::DeviceTransfer; "transfer")]
    #[test_case("device-transfer", Purpose::DeviceTransfer; "transfer hyphen")]
    #[test_case("device_transfer", Purpose::DeviceTransfer; "transfer underscore")]
    fn cli_parse_purpose(purpose_flag: &str, expected_purpose: Purpose) {
        let input = [EXECUTABLE_NAME, "filename", "--purpose", purpose_flag];
        let cli = Cli::try_parse_from(input).expect("parse failed");
        assert_eq!(cli.purpose, expected_purpose);
    }
}
