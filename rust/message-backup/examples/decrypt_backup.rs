//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Read as _;

use clap::Parser;
use clap_stdin::FileOrStdin;
use libsignal_message_backup::frame::{CursorFactory, FramesReader};

#[path = "../src/bin/support/mod.rs"]
mod support;
use support::KeyArgs;

#[derive(Parser)]
/// Decrypts and decompresses an encrypted backup file.
///
/// If no key is provided, the default testing key is assumed.
struct CliArgs {
    /// the file to read from, or '-' to read from stdin
    input: FileOrStdin,

    #[command(flatten)]
    key_args: KeyArgs,
}

fn main() {
    let CliArgs { input, key_args } = CliArgs::parse();

    let key = key_args.into_key_or_default();

    eprintln!("reading from {:?}", input.filename());

    let contents = read_file(input);
    eprintln!("read {} bytes", contents.len());

    let frames = futures::executor::block_on(async {
        let reader = FramesReader::new(&key, CursorFactory::new(&contents))
            .await
            .unwrap();
        libsignal_message_backup::backup::convert_to_json(reader)
            .await
            .unwrap()
    });
    println!("{:#}", serde_json::Value::Array(frames));
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
