//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::zkgroup::groups::GroupSecretParams;
use ::zkgroup::profiles::ExpiringProfileKeyCredential;
use ::zkgroup::{RANDOMNESS_LEN, ServerPublicParams};
use libsignal_net_chat::api::registration::SignedPreKeyBody;
use libsignal_protocol::error::Result;
use libsignal_protocol::*;

use crate::*;

bridge_get!(SessionRecord::alice_base_key -> &[u8], ffi = false, node = false);

/// cbindgen: ignore
type SignedPublicPreKey = SignedPreKeyBody<Box<[u8]>>;

#[bridge_fn]
fn TESTING_SignedPublicPreKey_CheckBridgesCorrectly(
    source_public_key: &PublicKey,
    signed_pre_key: SignedPublicPreKey,
) {
    let SignedPreKeyBody {
        key_id,
        public_key,
        signature,
    } = signed_pre_key;

    assert_eq!(key_id, 42);
    assert_eq!(
        hex::encode(public_key),
        hex::encode(source_public_key.serialize())
    );
    assert_eq!(&*signature, b"signature");
}

// We use this to test the *server* side of things, and the server is written in Java.
#[bridge_fn(ffi = false, node = false)]
fn TESTING_ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationVersionedDeterministic(
    server_public_params: &ServerPublicParams,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<ExpiringProfileKeyCredential>,
    new_version: bool,
) -> Vec<u8> {
    if new_version {
        ::zkgroup::serialize(
            &server_public_params.create_expiring_profile_key_credential_presentation::<{
                ::zkgroup::PRESENTATION_VERSION_4
            }>(
                *randomness,
                group_secret_params.into_inner(),
                profile_key_credential.into_inner(),
            ),
        )
    } else {
        ::zkgroup::serialize(
            &server_public_params.create_expiring_profile_key_credential_presentation::<{
                ::zkgroup::PRESENTATION_VERSION_3
            }>(
                *randomness,
                group_secret_params.into_inner(),
                profile_key_credential.into_inner(),
            )
        )
    }
}
