//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Both proto files in the proto folder specify the same package name, so they end up in the same .rs file.
include!(concat!(env!("OUT_DIR"), "/signal.keytrans.rs"));
