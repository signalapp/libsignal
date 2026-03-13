//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use clap::Parser;
use clap_stdin::FileOrStdin;
use futures::io::AllowStdIo;

#[derive(Parser)]
/// Compresses and encrypts an unencrypted backup file.
struct CliArgs {
    /// the file to read from, or '-' to read from stdin
    input: FileOrStdin,
}

fn main() {
    let CliArgs { input } = CliArgs::parse();

    eprintln!("reading from {:?}", input.filename());

    let frames = futures::executor::block_on(libsignal_message_backup::backup::convert_to_json(
        AllowStdIo::new(input.into_reader().expect("failed to open")),
    ))
    .expect("failed to convert");

    // Convert *back* into JSON values so that we can pretty-print.
    let frames = frames
        .into_iter()
        .map(|frame| serde_json::from_str(&frame).unwrap())
        .collect();
    print!("{:#}", serde_json::Value::Array(frames));
}
