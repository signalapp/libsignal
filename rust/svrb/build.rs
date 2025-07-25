//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use protobuf_codegen::Customize;

fn main() {
    const PROTOS: &[&str] = &[
        "src/proto/backup_metadata.proto",
        "src/proto/backup4.proto",
        "src/proto/svrb.proto",
    ];

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
        .protoc_extra_arg(
            // Enable optional fields. This isn't needed in the most recent
            // protobuf compiler version, but adding it lets us support older
            // versions that might be installed in CI or on developer machines.
            "--experimental_allow_proto3_optional",
        )
        .include("src")
        .inputs(PROTOS)
        .out_dir(&out_dir)
        .run_from_script();
}
