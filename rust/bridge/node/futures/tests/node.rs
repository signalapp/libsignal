//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// #![cfg(feature = "node-tests")]

use std::path::Path;
use std::process::Command;

fn main() {
    // Note: This is brittle; it relies on the node library getting built relative to the test executable.
    let mut library_path = std::env::current_exe()
        .expect("can get current executable path")
        .parent()
        .unwrap()
        .to_owned();
    for possible_library_name in &[
        "libsignal_neon_futures_tests.so",
        "libsignal_neon_futures_tests.dylib",
        "signal_neon_futures_tests.dll",
    ] {
        library_path.push(possible_library_name);
        if library_path.exists() {
            break;
        }
        library_path.pop();
    }
    assert!(
        library_path.is_file(),
        "at least one of these should exist (in {:?})",
        library_path
    );

    // Give the built library a .node extension by copying it to temp_dir.
    // It would be nice if we could pass this directly to Node, or use a symlink, but neither works.
    let node_library_path = std::env::temp_dir().join("signal_neon_futures_tests.node");
    std::fs::copy(library_path, &node_library_path).expect("can copy to temporary directory");

    let test_cases = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/node-tests");
    let status = Command::new("yarn")
        .arg("test")
        .env("SIGNAL_NEON_FUTURES_TEST_LIB", &node_library_path)
        .env("MALLOC_PERTURB_", "1") // Add glibc and macOS use-after-free detection.
        .env("MALLOC_SCRIBBLE", "1")
        .current_dir(&test_cases)
        .status()
        .expect("failed to run `yarn test`");
    if !status.success() {
        eprintln!(
            "\nSIGNAL_NEON_FUTURES_TEST_LIB={:?} yarn --cwd {:?} test\n",
            node_library_path, test_cases
        );
        panic!("Node tests failed");
    }
}
