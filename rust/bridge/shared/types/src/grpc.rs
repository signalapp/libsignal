//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use signal_grpc::GrpcClient;

#[cfg(all(not(target_os = "android"), feature = "jni"))]
use std::collections::HashMap;

#[cfg(all(not(target_os = "android"), feature = "jni"))]
pub struct GrpcHeaders(pub HashMap<String, Vec<String>>);

bridge_as_handle!(GrpcClient, mut = true);
