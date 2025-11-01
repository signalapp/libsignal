//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

fn main() {
    const SERVICE_PROTOS: &[&str] = &[
        "proto/org/signal/chat/account.proto",
        "proto/org/signal/chat/calling.proto",
        "proto/org/signal/chat/credentials.proto",
        "proto/org/signal/chat/device.proto",
        "proto/org/signal/chat/keys.proto",
        "proto/org/signal/chat/payments.proto",
        "proto/org/signal/chat/profile.proto",
    ];

    tonic_build::configure()
        .build_server(false)
        .build_transport(false)
        .compile_protos(SERVICE_PROTOS, &["proto/"])
        .unwrap_or_else(|e| panic!("{e}"));
}
