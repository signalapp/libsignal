//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

extern crate cbindgen;

use std::env;
use std::path::Path;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Walk up from OUT_DIR to find where to put signal_ffi.h.
    // Cargo doesn't officially support this, but we'll know if it breaks.
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);
    assert!(out_path.ancestors().nth(2).unwrap().ends_with("build"));
    let header_path = out_path.ancestors().nth(3).unwrap().join("signal_ffi.h");

    cbindgen::generate(crate_dir)
        .unwrap()
        .write_to_file(header_path);
}
