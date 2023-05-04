//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "src/proto/proxy.proto",
    ];
    tonic_build::configure()
        .build_server(false).compile(
        &protos,
        &["src"],
    )?;
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
    Ok(())
}
