//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{
    Context, IdentityKeyStore, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyStore,
};

use crate::consts::MAX_FORWARD_JUMPS;
use crate::crypto;
use crate::curve;
use crate::error::Result;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use crate::ratchet::{ChainKey, MessageKeys};
use crate::session;
use crate::state::SessionState;
use crate::storage::Direction;

use rand::{CryptoRng, Rng};

pub async fn message_encrypt(
    ptext: &[u8],
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<CiphertextMessage> {
    let mut session_record = session_store
        .load_session(&remote_address, ctx)
        .await?
        .ok_or(SignalProtocolError::SessionNotFound)?;
    let session_state = session_record.session_state_mut()?;

    let chain_key = session_state.get_sender_chain_key()?;

    let message_keys = chain_key.message_keys()?;

    let sender_ephemeral = session_state.sender_ratchet_key()?;
    let previous_counter = session_state.previous_counter()?;
    let session_version = session_state.session_version()? as u8;

    let local_identity_key = session_state.local_identity_key()?;
    let their_identity_key = session_state
        .remote_identity_key()?
        .ok_or(SignalProtocolError::InvalidSessionStructure)?;

    let ctext = crypto::aes_256_cbc_encrypt(ptext, message_keys.cipher_key(), message_keys.iv())?;

    let message = if let Some(items) = session_state.unacknowledged_pre_key_message_items()? {
        let local_registration_id = session_state.local_registration_id()?;

        let message = SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            sender_ephemeral,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
        )?;

        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::new(
            session_version,
            local_registration_id,
            items.pre_key_id()?,
            items.signed_pre_key_id()?,
            *items.base_key()?,
            local_identity_key,
            message,
        )?)
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            sender_ephemeral,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
        )?)
    };

    session_state.set_sender_chain_key(&chain_key.next_chain_key()?)?;

    // XXX why is this check after everything else?!!
    if !identity_store
        .is_trusted_identity(
            &remote_address,
            &their_identity_key,
            Direction::Sending,
            ctx,
        )
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    // XXX this could be combined with the above call to the identity store (in a new API)
    identity_store
        .save_identity(&remote_address, &their_identity_key, ctx)
        .await?;

    session_store
        .store_session(&remote_address, &session_record, ctx)
        .await?;
    Ok(message)
}

pub async fn message_decrypt<R: Rng + CryptoRng>(
    ciphertext: &CiphertextMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    csprng: &mut R,
    ctx: Context,
) -> Result<Vec<u8>> {
    match ciphertext {
        CiphertextMessage::SignalMessage(m) => {
            message_decrypt_signal(
                m,
                remote_address,
                session_store,
                identity_store,
                csprng,
                ctx,
            )
            .await
        }
        CiphertextMessage::PreKeySignalMessage(m) => {
            message_decrypt_prekey(
                m,
                remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                csprng,
                ctx,
            )
            .await
        }
        _ => Err(SignalProtocolError::InvalidArgument(
            "SessionCipher::decrypt cannot decrypt this message type".to_owned(),
        )),
    }
}

pub async fn message_decrypt_prekey<R: Rng + CryptoRng>(
    ciphertext: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    csprng: &mut R,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(&remote_address, ctx)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    let pre_key_id = session::process_prekey(
        ciphertext,
        &remote_address,
        &mut session_record,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        ctx,
    )
    .await?;

    let ptext = decrypt_message_with_record(&mut session_record, ciphertext.message(), csprng)?;

    session_store
        .store_session(&remote_address, &session_record, ctx)
        .await?;

    if let Some(pre_key_id) = pre_key_id {
        pre_key_store.remove_pre_key(pre_key_id, ctx).await?;
    }

    Ok(ptext)
}

pub async fn message_decrypt_signal<R: Rng + CryptoRng>(
    ciphertext: &SignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    csprng: &mut R,
    ctx: Context,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(&remote_address, ctx)
        .await?
        .ok_or(SignalProtocolError::SessionNotFound)?;

    let ptext = decrypt_message_with_record(&mut session_record, ciphertext, csprng)?;

    // Why are we performing this check after decryption instead of before?
    let their_identity_key = session_record
        .session_state()?
        .remote_identity_key()?
        .ok_or(SignalProtocolError::InvalidSessionStructure)?;

    if !identity_store
        .is_trusted_identity(
            &remote_address,
            &their_identity_key,
            Direction::Receiving,
            ctx,
        )
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    identity_store
        .save_identity(&remote_address, &their_identity_key, ctx)
        .await?;

    session_store
        .store_session(&remote_address, &session_record, ctx)
        .await?;

    Ok(ptext)
}

fn decrypt_message_with_record<R: Rng + CryptoRng>(
    record: &mut SessionRecord,
    ciphertext: &SignalMessage,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    let mut current_state = record.session_state()?.clone();

    let result = decrypt_message_with_state(&mut current_state, ciphertext, csprng);

    match result {
        Ok(ptext) => {
            record.set_session_state(current_state)?; // update the state
            return Ok(ptext);
        }
        Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
            return result;
        }
        Err(_) => {}
    }

    let mut updated_session = None;

    for (idx, previous) in record.previous_session_states()?.enumerate() {
        let mut updated = previous.clone();

        let result = decrypt_message_with_state(&mut updated, ciphertext, csprng);

        match result {
            Ok(ptext) => {
                updated_session = Some((ptext, idx, updated));
                break;
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            _ => {}
        }
    }

    if let Some((ptext, idx, updated_session)) = updated_session {
        record.promote_old_session(idx, updated_session)?;
        Ok(ptext)
    } else {
        Err(SignalProtocolError::InvalidMessage(
            "decryption failed; no matching session state",
        ))
    }
}

fn decrypt_message_with_state<R: Rng + CryptoRng>(
    state: &mut SessionState,
    ciphertext: &SignalMessage,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    if !state.has_sender_chain()? {
        return Err(SignalProtocolError::InvalidSessionStructure);
    }

    let ciphertext_version = ciphertext.message_version() as u32;
    if ciphertext_version != state.session_version()? {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            ciphertext_version,
        ));
    }

    let their_ephemeral = ciphertext.sender_ratchet_key();
    let counter = ciphertext.counter();
    let chain_key = get_or_create_chain_key(state, their_ephemeral, csprng)?;
    let message_keys = get_or_create_message_key(state, their_ephemeral, &chain_key, counter)?;

    let their_identity_key = state
        .remote_identity_key()?
        .ok_or(SignalProtocolError::InvalidSessionStructure)?;

    let mac_valid = ciphertext.verify_mac(
        &their_identity_key,
        &state.local_identity_key()?,
        message_keys.mac_key(),
    )?;

    if !mac_valid {
        return Err(SignalProtocolError::InvalidCiphertext);
    }

    let ptext = crypto::aes_256_cbc_decrypt(
        ciphertext.body(),
        message_keys.cipher_key(),
        message_keys.iv(),
    )?;

    state.clear_unacknowledged_pre_key_message()?;

    Ok(ptext)
}

fn get_or_create_chain_key<R: Rng + CryptoRng>(
    state: &mut SessionState,
    their_ephemeral: &curve::PublicKey,
    csprng: &mut R,
) -> Result<ChainKey> {
    if let Some(chain) = state.get_receiver_chain_key(their_ephemeral)? {
        return Ok(chain);
    }

    let root_key = state.root_key()?;
    let our_ephemeral = state.sender_ratchet_private_key()?;
    let receiver_chain = root_key.create_chain(their_ephemeral, &our_ephemeral)?;
    let our_new_ephemeral = curve::KeyPair::generate(csprng);
    let sender_chain = receiver_chain
        .0
        .create_chain(their_ephemeral, &our_new_ephemeral.private_key)?;

    state.set_root_key(&sender_chain.0)?;
    state.add_receiver_chain(their_ephemeral, &receiver_chain.1)?;

    let current_index = state.get_sender_chain_key()?.index();
    let previous_index = if current_index > 0 {
        current_index - 1
    } else {
        0
    };
    state.set_previous_counter(previous_index)?;
    state.set_sender_chain(&our_new_ephemeral, &sender_chain.1)?;

    Ok(receiver_chain.1)
}

fn get_or_create_message_key(
    state: &mut SessionState,
    their_ephemeral: &curve::PublicKey,
    chain_key: &ChainKey,
    counter: u32,
) -> Result<MessageKeys> {
    let chain_index = chain_key.index();

    if chain_index > counter {
        return match state.get_message_keys(their_ephemeral, counter)? {
            Some(keys) => Ok(keys),
            None => Err(SignalProtocolError::DuplicatedMessage(chain_index, counter)),
        };
    }

    assert!(chain_index <= counter);

    let jump = (counter - chain_index) as usize;

    if jump > MAX_FORWARD_JUMPS {
        return Err(SignalProtocolError::InvalidMessage(
            "message from too far into the future",
        ));
    }

    let mut chain_key = chain_key.clone();

    while chain_key.index() < counter {
        let message_keys = chain_key.message_keys()?;
        state.set_message_keys(their_ephemeral, &message_keys)?;
        chain_key = chain_key.next_chain_key()?;
    }

    state.set_receiver_chain_key(their_ephemeral, &chain_key.next_chain_key()?)?;
    Ok(chain_key.message_keys()?)
}
