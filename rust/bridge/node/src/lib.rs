//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge::*;
use neon::prelude::*;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("PrivateKey_generate", node_PrivateKey_generate)?;
    cx.export_function("PrivateKey_deserialize", node_PrivateKey_deserialize)?;
    cx.export_function("PrivateKey_serialize", node_PrivateKey_serialize)?;
    cx.export_function("PrivateKey_sign", node_PrivateKey_sign)?;
    cx.export_function("PrivateKey_agree", node_PrivateKey_agree)?;
    cx.export_function("PrivateKey_getPublicKey", node_PrivateKey_getPublicKey)?;

    cx.export_function("PublicKey_verify", node_PublicKey_verify)?;
    cx.export_function("PublicKey_deserialize", node_PublicKey_deserialize)?;
    cx.export_function("PublicKey_serialize", node_PublicKey_serialize)?;
    Ok(())
}
