//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    let protos = ["src/proto/backup.proto"];
    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_extra_arg(
            // Enable optional fields. This isn't needed in the most recent
            // protobuf compiler version, but adding it lets us support older
            // versions that might be installed in CI or on developer machines.
            "--experimental_allow_proto3_optional",
        )
        .include("src")
        .inputs(protos)
        .cargo_out_dir("protos")
        .run_from_script();
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
