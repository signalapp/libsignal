//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::path::Path;
use std::process::Command;

pub fn run(action: &str) {
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
        "at least one of these should exist (in {library_path:?})"
    );

    // Give the built library a .node extension by copying it to temp_dir.
    // It would be nice if we could pass this directly to Node, or use a symlink, but neither works.
    let node_library_path = std::env::temp_dir().join("signal_neon_futures_tests.node");
    std::fs::copy(library_path, &node_library_path).expect("can copy to temporary directory");

    if std::env::var_os("RUST_BACKTRACE").is_some_and(|val| val != "0") {
        eprintln!("warning: RUST_BACKTRACE is overridden to 0 while running these tests");
        eprintln!("note: use `npm run test` directly to turn RUST_BACKTRACE on");
    }

    // Use cfg!(debug_assertions) as a proxy for "we're smoke testing benchmarks, not actually
    // running them". This only affects the benchmarks, but it definitely helps there.
    let smoke_test_only = if cfg!(debug_assertions) { "1" } else { "" };

    let test_cases = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/node-tests");
    let status = Command::new("npm")
        .arg("run")
        .arg(action)
        .env("SIGNAL_NEON_FUTURES_TEST_LIB", &node_library_path)
        .env("SIGNAL_NEON_FUTURES_TEST_SMOKE_ONLY", smoke_test_only)
        .env("MALLOC_PERTURB_", "1") // Add glibc and macOS use-after-free detection.
        .env("MALLOC_SCRIBBLE", "1")
        .env("RUST_BACKTRACE", "0") // Don't slow down tests by printing backtraces.
        .current_dir(&test_cases)
        .status()
        .expect("failed to run `npm run test`");
    if !status.success() {
        eprintln!(
            "\ncd {test_cases:?} && SIGNAL_NEON_FUTURES_TEST_LIB={node_library_path:?} npm run {action}\n"
        );
        panic!("Node tests failed");
    }
}
