//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_provisioning::{
    ProvisioningError, RecvProvisionCiphertextState, encrypt_provision_message,
};
use rand::TryRngCore as _;

use crate::support::*;
use crate::*;

bridge_handle_fns!(RecvProvisionCiphertextState, clone = false);

// Node has no nice converter for returning an owned handle
#[bridge_fn(nice = true, nice_node = false)]
fn RecvProvisionCiphertextState_Generate() -> RecvProvisionCiphertextState {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    RecvProvisionCiphertextState::generate(&mut rng)
}

#[bridge_fn(nice = true)]
fn RecvProvisionCiphertextState_GetPublicKey(
    state: BridgeHandleRef<'_, RecvProvisionCiphertextState>,
) -> [u8; 33] {
    state.public_key()
}

#[bridge_fn(nice = true)]
fn RecvProvisionCiphertextState_DecryptEnvelope(
    state: BridgeHandleRef<'_, RecvProvisionCiphertextState>,
    envelope: &[u8],
) -> Result<Vec<u8>, ProvisioningError> {
    state.decrypt_envelope(envelope)
}

#[bridge_fn(nice = true)]
fn Provisioning_EncryptProvisionMessage(
    secondary_public_key: [u8; 33],
    provision_message: &[u8],
) -> Result<Vec<u8>, ProvisioningError> {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    encrypt_provision_message(&mut rng, &secondary_public_key, provision_message)
}
