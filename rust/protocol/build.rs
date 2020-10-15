//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

fn main() {
    let protos = [
        "src/proto/fingerprint.proto",
        "src/proto/storage.proto",
        "src/proto/wire.proto",
    ];
    prost_build::compile_protos(&protos, &["src"]).unwrap();
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
