//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "../../proto/org/signal/chat/calling.proto",
        "../../proto/org/signal/chat/common.proto",
        "../../proto/org/signal/chat/credentials.proto",
        "../../proto/org/signal/chat/device.proto",
        "../../proto/org/signal/chat/keys.proto",
        "../../proto/org/signal/chat/payments.proto",
        "../../proto/org/signal/chat/profile.proto",
    ];
    tonic_build::configure()
        .build_server(false)
        .compile(&protos, &["../../proto"])?;
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
    Ok(())
}
