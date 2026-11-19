//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_bridge_types::provisioning::ProvisioningPublicKey;
use libsignal_core::curve::KeyType;
use libsignal_protocol::SignalProtocolError;
use libsignal_provisioning::{
    ProvisioningError, RecvProvisionCiphertextState, encrypt_provision_message,
};
use rand::TryRngCore as _;

use crate::support::*;
use crate::*;

bridge_handle_fns!(ProvisioningPublicKey, clone = false);
bridge_handle_fns!(RecvProvisionCiphertextState, clone = false);

// No `nice`. The app-language constructors need the raw handle.
#[bridge_fn]
fn ProvisioningPublicKey_Deserialize(pubkey_bytes: &[u8]) -> ProvisioningPublicKey {
    ProvisioningPublicKey(pubkey_bytes.into())
}

#[bridge_fn(nice = true)]
fn ProvisioningPublicKey_Serialize(key: BridgeHandleRef<'_, ProvisioningPublicKey>) -> Vec<u8> {
    key.0.to_vec()
}

// Node has no nice converter for returning an owned handle
#[bridge_fn(nice = true, nice_node = false)]
fn RecvProvisionCiphertextState_Generate() -> RecvProvisionCiphertextState {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    RecvProvisionCiphertextState::generate(&mut rng)
}

// Node has no `nice` converter for returning an owned handle
#[bridge_fn(nice = true, nice_node = false)]
fn RecvProvisionCiphertextState_GetPublicKey(
    state: BridgeHandleRef<'_, RecvProvisionCiphertextState>,
) -> ProvisioningPublicKey {
    ProvisioningPublicKey(state.public_key().into())
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
    secondary_public_key: BridgeHandleRef<'_, ProvisioningPublicKey>,
    provision_message: &[u8],
) -> Result<Vec<u8>, SignalProtocolError> {
    // This function only fails on a bad public key. We report that explicitly as a key error, since
    // apps treat a ProvisioningError as an invalid message.
    let pubkey_bytes = &*secondary_public_key.0;
    let secondary_public_key = pubkey_bytes
        .try_into()
        .map_err(|_| SignalProtocolError::BadKeyLength(KeyType::Djb, pubkey_bytes.len()))?;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    encrypt_provision_message(&mut rng, secondary_public_key, provision_message).map_err(
        |e| match e {
            ProvisioningError::InvalidPubkeyVer(key_type) => {
                SignalProtocolError::BadKeyType(key_type)
            }
            ProvisioningError::MalformedPubkey
            | ProvisioningError::InvalidProtobuf
            | ProvisioningError::MalformedBody
            | ProvisioningError::InvalidBodyVer(_)
            | ProvisioningError::NonContributoryKey
            | ProvisioningError::InvalidMac
            | ProvisioningError::InvalidPadding => {
                unreachable!("encryption of a 33-byte key only fails on its type byte, but got {e}")
            }
        },
    )
}
