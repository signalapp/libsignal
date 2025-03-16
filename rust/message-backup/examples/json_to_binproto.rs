//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{Read as _, Write as _};

use assert_matches::assert_matches;
use clap::Parser;
use clap_stdin::FileOrStdin;

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
        // Work around https://github.com/callum-oakley/json5-rs/issues/21
        .replace("\u{2028}", "\\u2028")
        .replace("\u{2029}", "\\u2029");
    let contents = json5::from_str(&json_input).expect("invalid JSON");

    let contents = assert_matches!(contents, serde_json::Value::Array(contents) => contents);
    let serialized =
        libsignal_message_backup::backup::convert_from_json(contents).expect("failed to convert");

    std::io::stdout()
        .write_all(&serialized)
        .expect("failed to write");
}

fn read_file(input: FileOrStdin) -> Vec<u8> {
    let source = input.filename().to_owned();
    let mut contents = Vec::new();
    input
        .into_reader()
        .unwrap_or_else(|e| panic!("failed to read {source:?}: {e}"))
        .read_to_end(&mut contents)
        .expect("IO error");
    contents
}
