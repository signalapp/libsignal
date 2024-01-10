//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    const PROTOS: &[&str] = &["src/proto/backup.proto", "src/proto/test.proto"];
    const PROTOS_DIR: &str = "protos";

    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_extra_arg(
            // Enable optional fields. This isn't needed in the most recent
            // protobuf compiler version, but adding it lets us support older
            // versions that might be installed in CI or on developer machines.
            "--experimental_allow_proto3_optional",
        )
        .include("src")
        .inputs(PROTOS)
        .cargo_out_dir(PROTOS_DIR)
        .run_from_script();

    // Mark the test.proto module as test-only.
    let out_mod_rs = format!("{}/{PROTOS_DIR}/mod.rs", std::env::var("OUT_DIR").unwrap());
    let mut contents = std::fs::read_to_string(&out_mod_rs).unwrap();
    let insert_pos = contents.find("pub mod test;").unwrap_or(0);

    contents.insert_str(insert_pos, "\n#[cfg(test)] // only for testing\n");
    std::fs::write(out_mod_rs, contents).unwrap();

    for proto in PROTOS {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
