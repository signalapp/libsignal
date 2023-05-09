//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{
    kem, Context, Direction, IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyStore,
    PreKeyBundle, PreKeyId, PreKeySignalMessage, PreKeyStore, ProtocolAddress, Result,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyStore,
};

use crate::ratchet;
use crate::ratchet::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::state::GenericSignedPreKey;
use rand::{CryptoRng, Rng};

#[derive(Default)]
pub struct PreKeysUsed {
    pub pre_key_id: Option<PreKeyId>,
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
}

/*
These functions are on SessionBuilder in Java

However using SessionBuilder + SessionCipher at the same time causes
&mut sharing issues. And as SessionBuilder has no actual state beyond
its reference to the various data stores, instead the functions are
free standing.
 */

pub async fn process_prekey(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
    kyber_prekey_store: &mut dyn KyberPreKeyStore,
    ctx: Context,
) -> Result<PreKeysUsed> {
    let their_identity_key = message.identity_key();

    if !identity_store
        .is_trusted_identity(
            remote_address,
            their_identity_key,
            Direction::Receiving,
            ctx,
        )
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    let pre_keys_used = process_prekey_impl(
        message,
        remote_address,
        session_record,
        signed_prekey_store,
        kyber_prekey_store,
        pre_key_store,
        identity_store,
        ctx,
    )
    .await?;

    identity_store
        .save_identity(remote_address, their_identity_key, ctx)
        .await?;

    Ok(pre_keys_used)
}

async fn process_prekey_impl(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
    kyber_prekey_store: &mut dyn KyberPreKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<PreKeysUsed> {
    if session_record.has_session_state(
        message.message_version() as u32,
        &message.base_key().serialize(),
    )? {
        // We've already setup a session for this message, letting bundled message fall through
        return Ok(Default::default());
    }

    let our_signed_pre_key_pair = signed_prekey_store
        .get_signed_pre_key(message.signed_pre_key_id(), ctx)
        .await?
        .key_pair()?;

    // Because async closures are unstable
    let our_kyber_pre_key_pair: Option<kem::KeyPair>;
    if let Some(kyber_pre_key_id) = message.kyber_pre_key_id() {
        our_kyber_pre_key_pair = Some(
            kyber_prekey_store
                .get_kyber_pre_key(kyber_pre_key_id, ctx)
                .await?
                .key_pair()?,
        );
    } else {
        our_kyber_pre_key_pair = None;
    }

    let our_one_time_pre_key_pair = if let Some(pre_key_id) = message.pre_key_id() {
        log::info!("processing PreKey message from {}", remote_address);
        Some(
            pre_key_store
                .get_pre_key(pre_key_id, ctx)
                .await?
                .key_pair()?,
        )
    } else {
        log::warn!(
            "processing PreKey message from {} which had no one-time prekey",
            remote_address
        );
        None
    };

    let parameters = BobSignalProtocolParameters::new(
        identity_store.get_identity_key_pair(ctx).await?,
        our_signed_pre_key_pair, // signed pre key
        our_one_time_pre_key_pair,
        our_signed_pre_key_pair, // ratchet key
        our_kyber_pre_key_pair,
        *message.identity_key(),
        *message.base_key(),
        message.kyber_ciphertext(),
    );

    session_record.archive_current_state()?;

    let mut new_session = ratchet::initialize_bob_session(&parameters)?;

    new_session.set_local_registration_id(identity_store.get_local_registration_id(ctx).await?);
    new_session.set_remote_registration_id(message.registration_id());
    new_session.set_alice_base_key(&message.base_key().serialize());

    session_record.promote_state(new_session);

    let pre_keys_used = PreKeysUsed {
        pre_key_id: message.pre_key_id(),
        kyber_pre_key_id: message.kyber_pre_key_id(),
    };
    Ok(pre_keys_used)
}

pub async fn process_prekey_bundle<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    bundle: &PreKeyBundle,
    mut csprng: &mut R,
    ctx: Context,
) -> Result<()> {
    let their_identity_key = bundle.identity_key()?;

    if !identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Sending, ctx)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    if !their_identity_key.public_key().verify_signature(
        &bundle.signed_pre_key_public()?.serialize(),
        bundle.signed_pre_key_signature()?,
    )? {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    if let Some(kyber_public) = bundle.kyber_pre_key_public()? {
        if !their_identity_key.public_key().verify_signature(
            kyber_public.serialize().as_ref(),
            bundle
                .kyber_pre_key_signature()?
                .expect("signature must be present"),
        )? {
            return Err(SignalProtocolError::SignatureValidationFailed);
        }
    }

    let mut session_record = session_store
        .load_session(remote_address, ctx)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    let our_base_key_pair = KeyPair::generate(&mut csprng);
    let their_signed_prekey = bundle.signed_pre_key_public()?;

    let their_one_time_prekey_id = bundle.pre_key_id()?;

    let our_identity_key_pair = identity_store.get_identity_key_pair(ctx).await?;

    let mut parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,
        our_base_key_pair,
        *their_identity_key,
        their_signed_prekey,
        their_signed_prekey,
    );
    if let Some(key) = bundle.pre_key_public()? {
        parameters.set_their_one_time_pre_key(key);
    }

    if let Some(key) = bundle.kyber_pre_key_public()? {
        parameters.set_their_kyber_pre_key(key);
    }

    let mut session = ratchet::initialize_alice_session(&parameters, csprng)?;

    log::info!(
        "set_unacknowledged_pre_key_message for: {} with preKeyId: {}",
        remote_address,
        their_one_time_prekey_id.map_or_else(|| "<none>".to_string(), |id| id.to_string())
    );

    session.set_unacknowledged_pre_key_message(
        their_one_time_prekey_id,
        bundle.signed_pre_key_id()?,
        &our_base_key_pair.public_key,
    );

    if let Some(kyber_pre_key_id) = bundle.kyber_pre_key_id()? {
        session.set_unacknowledged_kyber_pre_key_id(kyber_pre_key_id);
    }

    session.set_local_registration_id(identity_store.get_local_registration_id(ctx).await?);
    session.set_remote_registration_id(bundle.registration_id()?);
    session.set_alice_base_key(&our_base_key_pair.public_key.serialize());

    identity_store
        .save_identity(remote_address, their_identity_key, ctx)
        .await?;

    session_record.promote_state(session);

    session_store
        .store_session(remote_address, &session_record, ctx)
        .await?;

    Ok(())
}
