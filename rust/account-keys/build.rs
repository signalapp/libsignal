//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use protobuf_codegen::Customize;

fn main() {
    const PROTOS: &[&str] = &["src/proto/mfa_metadata.proto"];

    for proto in PROTOS {
        println!("cargo:rerun-if-changed={proto}");
    }

    let out_dir = format!(
        "{}/protos",
        std::env::var("OUT_DIR").expect("OUT_DIR env var not set")
    );
    std::fs::create_dir_all(&out_dir).expect("failed to create output directory");

    protobuf_codegen::Codegen::new()
        .customize(Customize::default().lite_runtime(true))
        .protoc()
        .include("src")
        .inputs(PROTOS)
        .out_dir(&out_dir)
        .run_from_script();
}
