//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// TODO: This re-export is because of the jni_arg_type macro expecting all bridging structs to
// appear in the jni module.
pub use crate::protocol::storage::{
    JavaIdentityKeyStore, JavaKyberPreKeyStore, JavaPreKeyStore, JavaSenderKeyStore,
    JavaSessionStore, JavaSignedPreKeyStore,
};
