//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Read as _;

pub mod args;

pub fn read_file(input: clap_stdin::FileOrStdin) -> Vec<u8> {
    let source = input.filename().to_owned();
    let mut contents = Vec::new();
    input
        .into_reader()
        .unwrap_or_else(|e| panic!("failed to read {source:?}: {e}"))
        .read_to_end(&mut contents)
        .expect("IO error");
    contents
}
