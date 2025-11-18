//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Write as _;

use assert_matches::assert_matches;
use clap::Parser;
use clap_stdin::FileOrStdin;
use libsignal_cli_utils::read_file;

#[derive(Parser)]
/// Compresses and encrypts an unencrypted backup file.
struct CliArgs {
    /// the file to read from, or '-' to read from stdin
    input: FileOrStdin,
}

fn main() {
    let CliArgs { input } = CliArgs::parse();

    eprintln!("reading from {:?}", input.filename());

    let json_input = String::from_utf8(read_file(input))
        .expect("not a string")
        // Work around https://github.com/callum-oakley/json5-rs/issues/21,
        // which persists in the serde_json5 fork.
        .replace("\u{2028}", "\\u2028")
        .replace("\u{2029}", "\\u2029");
    let contents = serde_json5::from_str(&json_input).expect("invalid JSON");

    let contents = assert_matches!(contents, serde_json::Value::Array(contents) => contents);
    let serialized =
        libsignal_message_backup::backup::convert_from_json(contents).expect("failed to convert");

    std::io::stdout()
        .write_all(&serialized)
        .expect("failed to write");
}
