//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
#![allow(clippy::derive_partial_eq_without_eq)]

// Both proto files in the proto folder specify the same package name, so they end up in the same .rs file.
include!(concat!(env!("OUT_DIR"), "/signal.keytrans.rs"));
