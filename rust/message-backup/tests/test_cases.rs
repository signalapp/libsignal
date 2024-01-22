//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use dir_test::{dir_test, Fixture};
use futures::io::AllowStdIo;

use libsignal_message_backup::{BackupReader, ReadResult};

#[dir_test(
    dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
    glob: "valid/*.binproto",
    loader: read_file_async,
    postfix: "binproto"
)]
fn is_valid_binproto(input: Fixture<AllowStdIo<std::fs::File>>) {
    let input = input.into_content();
    let mut reader = BackupReader::new_unencrypted(input);
    reader.visitor = |msg| println!("{msg:#?}");

    let ReadResult {
        result,
        found_unknown_fields,
    } = futures::executor::block_on(reader.read_all());
    assert_eq!(found_unknown_fields, Vec::new());

    let backup = result.expect("invalid backup");
    println!("got backup:\n{backup:#?}");
}

fn read_file_async(path: &str) -> AllowStdIo<std::fs::File> {
    let file = std::fs::File::open(path).expect("can read");
    AllowStdIo::new(file)
}
