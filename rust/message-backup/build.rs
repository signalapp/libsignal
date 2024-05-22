//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::Write as _;

use protobuf_codegen::{Customize, CustomizeCallback};

const DERIVE_LINE: &str = "#[derive(crate::unknown::visit_static::VisitUnknownFields)]";

struct DeriveVisitUnknownFields;

impl CustomizeCallback for DeriveVisitUnknownFields {
    fn field(&self, field: &protobuf::reflect::FieldDescriptor) -> Customize {
        Customize::default().before(&format!("#[field_name({:?})]", field.name()))
    }
    fn message(&self, _: &protobuf::reflect::MessageDescriptor) -> Customize {
        Customize::default().before(DERIVE_LINE)
    }
    fn enumeration(&self, _: &protobuf::reflect::EnumDescriptor) -> Customize {
        Customize::default().before(DERIVE_LINE)
    }
    fn oneof(&self, _: &protobuf::reflect::OneofDescriptor) -> Customize {
        Customize::default().before(DERIVE_LINE)
    }
}

fn main() {
    const PROTOS_DIR: &str = "protos";

    let out_dir = format!(
        "{}/{PROTOS_DIR}",
        std::env::var("OUT_DIR").expect("OUT_DIR env var not set")
    );
    std::fs::create_dir_all(&out_dir).expect("failed to create output directory");

    let make_codegen = || {
        let mut codegen = protobuf_codegen::Codegen::new();

        // Use the lite runtime to reduce code size, unless the full runtime is
        // needed for JSON conversion code.
        #[cfg(not(feature = "json"))]
        codegen.customize(Customize::default().lite_runtime(true));

        codegen
            .protoc()
            .protoc_extra_arg(
                // Enable optional fields. This isn't needed in the most recent
                // protobuf compiler version, but adding it lets us support older
                // versions that might be installed in CI or on developer machines.
                "--experimental_allow_proto3_optional",
            )
            .customize_callback(DeriveVisitUnknownFields)
            .include("src")
            .out_dir(&out_dir);
        codegen
    };

    // For the test-only protos, use the full runtime instead of the lite
    // runtime. This lets us test the dynamic and static unknown field dispatch.
    const TEST_PROTOS: &[&str] = &["src/proto/test.proto"];
    make_codegen()
        .inputs(TEST_PROTOS)
        .customize(Customize::default().lite_runtime(false))
        .run_from_script();

    const PROTOS: &[&str] = &["src/proto/backup.proto"];
    make_codegen().inputs(PROTOS).run_from_script();

    // Add the test.proto module to mod.rs as test-only.
    let out_mod_rs = format!("{out_dir}/mod.rs");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&out_mod_rs)
        .unwrap_or_else(|e| panic!("expected {out_mod_rs} to be writable, got {e}"))
        .write_all(b" #[cfg(test)] pub mod test; ")
        .expect("failed to write");

    for proto in PROTOS.iter().chain(TEST_PROTOS) {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
