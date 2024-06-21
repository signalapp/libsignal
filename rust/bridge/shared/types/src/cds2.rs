//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(all(not(target_os = "android"), feature = "jni"))]
use std::collections::HashMap;

#[cfg(all(not(target_os = "android"), feature = "jni"))]
pub struct Cds2Metrics(pub HashMap<String, i64>);
