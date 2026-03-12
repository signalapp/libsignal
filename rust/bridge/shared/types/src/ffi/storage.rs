//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::protocol::storage::{
    FfiBridgeIdentityKeyStoreStruct, FfiBridgeKyberPreKeyStoreStruct, FfiBridgePreKeyStoreStruct,
    FfiBridgeSenderKeyStoreStruct, FfiBridgeSessionStoreStruct, FfiBridgeSignedPreKeyStoreStruct,
};

// TODO: These aliases are because of the ffi_arg_type macro expecting all bridging structs to use a
// particular naming scheme; eventually we should be able to remove them.
pub type FfiIdentityKeyStoreStruct = FfiBridgeIdentityKeyStoreStruct;
pub type FfiPreKeyStoreStruct = FfiBridgePreKeyStoreStruct;
pub type FfiSignedPreKeyStoreStruct = FfiBridgeSignedPreKeyStoreStruct;
pub type FfiKyberPreKeyStoreStruct = FfiBridgeKyberPreKeyStoreStruct;
pub type FfiSenderKeyStoreStruct = FfiBridgeSenderKeyStoreStruct;
pub type FfiSessionStoreStruct = FfiBridgeSessionStoreStruct;
