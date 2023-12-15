//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    let protos = ["src/proto/backup.proto"];
    let mut prost_build = prost_build::Config::new();
    // Enable optional fields. This isn't needed in the most recent protobuf
    // compiler version, but adding it lets us support older versions that might
    // be installed in CI or on developer machines.
    prost_build.protoc_arg("--experimental_allow_proto3_optional");
    prost_build
        .compile_protos(&protos, &["src"])
        .expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
