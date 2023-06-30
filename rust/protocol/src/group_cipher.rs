//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;

use rand::{CryptoRng, Rng};
use uuid::Uuid;

use crate::protocol::SENDERKEY_MESSAGE_CURRENT_VERSION;
use crate::sender_keys::{SenderKeyState, SenderMessageKey};
use crate::{
    consts, CiphertextMessageType, Context, KeyPair, ProtocolAddress, Result,
    SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord, SenderKeyStore,
    SignalProtocolError,
};

pub async fn group_encrypt<R: Rng + CryptoRng>(
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    plaintext: &[u8],
    csprng: &mut R,
    ctx: Context,
) -> Result<SenderKeyMessage> {
    let mut record = sender_key_store
        .load_sender_key(sender, distribution_id, ctx)
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState { distribution_id })?;

    let sender_key_state = record
        .sender_key_state_mut()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    let sender_chain_key = sender_key_state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    let message_keys = sender_chain_key.sender_message_key();

    let ciphertext =
        signal_crypto::aes_256_cbc_encrypt(plaintext, message_keys.cipher_key(), message_keys.iv())
            .map_err(|_| {
                log::error!(
                    "outgoing sender key state corrupt for distribution ID {}",
                    distribution_id,
                );
                SignalProtocolError::InvalidSenderKeySession { distribution_id }
            })?;

    let signing_key = sender_key_state
        .signing_key_private()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    let skm = SenderKeyMessage::new(
        sender_key_state.message_version() as u8,
        distribution_id,
        sender_key_state.chain_id(),
        message_keys.iteration(),
        ciphertext.into_boxed_slice(),
        csprng,
        &signing_key,
    )?;

    sender_key_state.set_sender_chain_key(sender_chain_key.next());

    sender_key_store
        .store_sender_key(sender, distribution_id, &record, ctx)
        .await?;

    Ok(skm)
}

fn get_sender_key(
    state: &mut SenderKeyState,
    iteration: u32,
    distribution_id: Uuid,
) -> Result<SenderMessageKey> {
    let sender_chain_key = state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession { distribution_id })?;
    let current_iteration = sender_chain_key.iteration();

    if current_iteration > iteration {
        if let Some(smk) = state.remove_sender_message_key(iteration) {
            return Ok(smk);
        } else {
            log::info!(
                "SenderKey distribution {} Duplicate message for iteration: {}",
                distribution_id,
                iteration
            );
            return Err(SignalProtocolError::DuplicatedMessage(
                current_iteration,
                iteration,
            ));
        }
    }

    let jump = (iteration - current_iteration) as usize;
    if jump > consts::MAX_FORWARD_JUMPS {
        log::error!(
            "SenderKey distribution {} Exceeded future message limit: {}, current iteration: {})",
            distribution_id,
            consts::MAX_FORWARD_JUMPS,
            current_iteration
        );
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::SenderKey,
            "message from too far into the future",
        ));
    }

    let mut sender_chain_key = sender_chain_key;

    while sender_chain_key.iteration() < iteration {
        state.add_sender_message_key(&sender_chain_key.sender_message_key());
        sender_chain_key = sender_chain_key.next();
    }

    state.set_sender_chain_key(sender_chain_key.next());
    Ok(sender_chain_key.sender_message_key())
}

pub async fn group_decrypt(
    skm_bytes: &[u8],
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
    ctx: Context,
) -> Result<Vec<u8>> {
    let skm = SenderKeyMessage::try_from(skm_bytes)?;

    let distribution_id = skm.distribution_id();
    let chain_id = skm.chain_id();

    let mut record = sender_key_store
        .load_sender_key(sender, skm.distribution_id(), ctx)
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState { distribution_id })?;

    let sender_key_state = match record.sender_key_state_for_chain_id(chain_id) {
        Some(state) => state,
        None => {
            log::error!(
                "SenderKey distribution {} could not find chain ID {} (known chain IDs: {:?})",
                distribution_id,
                chain_id,
                record.chain_ids_for_logging().collect::<Vec<_>>(),
            );
            return Err(SignalProtocolError::NoSenderKeyState { distribution_id });
        }
    };

    let message_version = skm.message_version() as u32;
    if message_version != sender_key_state.message_version() {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            message_version,
        ));
    }

    let signing_key = sender_key_state
        .signing_key_public()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;
    if !skm.verify_signature(&signing_key)? {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let sender_key = get_sender_key(sender_key_state, skm.iteration(), distribution_id)?;

    let plaintext = match signal_crypto::aes_256_cbc_decrypt(
        skm.ciphertext(),
        sender_key.cipher_key(),
        sender_key.iv(),
    ) {
        Ok(plaintext) => plaintext,
        Err(signal_crypto::DecryptionError::BadKeyOrIv) => {
            log::error!(
                "incoming sender key state corrupt for {}, distribution ID {}, chain ID {}",
                sender,
                distribution_id,
                chain_id,
            );
            return Err(SignalProtocolError::InvalidSenderKeySession { distribution_id });
        }
        Err(signal_crypto::DecryptionError::BadCiphertext(msg)) => {
            log::error!("sender key decryption failed: {}", msg);
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::SenderKey,
                "decryption failed",
            ));
        }
    };

    sender_key_store
        .store_sender_key(sender, distribution_id, &record, ctx)
        .await?;

    Ok(plaintext)
}

pub async fn process_sender_key_distribution_message(
    sender: &ProtocolAddress,
    skdm: &SenderKeyDistributionMessage,
    sender_key_store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<()> {
    let distribution_id = skdm.distribution_id()?;
    log::info!(
        "{} Processing SenderKey distribution {} with chain ID {}",
        sender,
        distribution_id,
        skdm.chain_id()?
    );

    let mut sender_key_record = sender_key_store
        .load_sender_key(sender, distribution_id, ctx)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    sender_key_record.add_sender_key_state(
        skdm.message_version(),
        skdm.chain_id()?,
        skdm.iteration()?,
        skdm.chain_key()?,
        *skdm.signing_key()?,
        None,
    );
    sender_key_store
        .store_sender_key(sender, distribution_id, &sender_key_record, ctx)
        .await?;
    Ok(())
}

pub async fn create_sender_key_distribution_message<R: Rng + CryptoRng>(
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    sender_key_store: &mut dyn SenderKeyStore,
    csprng: &mut R,
    ctx: Context,
) -> Result<SenderKeyDistributionMessage> {
    let sender_key_record = sender_key_store
        .load_sender_key(sender, distribution_id, ctx)
        .await?;

    let sender_key_record = match sender_key_record {
        Some(record) => record,
        None => {
            // libsignal-protocol-java uses 31-bit integers for sender key chain IDs
            let chain_id = (csprng.gen::<u32>()) >> 1;
            log::info!(
                "Creating SenderKey for distribution {} with chain ID {}",
                distribution_id,
                chain_id
            );

            let iteration = 0;
            let sender_key: [u8; 32] = csprng.gen();
            let signing_key = KeyPair::generate(csprng);
            let mut record = SenderKeyRecord::new_empty();
            record.add_sender_key_state(
                SENDERKEY_MESSAGE_CURRENT_VERSION,
                chain_id,
                iteration,
                &sender_key,
                signing_key.public_key,
                Some(signing_key.private_key),
            );
            sender_key_store
                .store_sender_key(sender, distribution_id, &record, ctx)
                .await?;
            record
        }
    };

    let state = sender_key_record
        .sender_key_state()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;
    let sender_chain_key = state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    SenderKeyDistributionMessage::new(
        state.message_version() as u8,
        distribution_id,
        state.chain_id(),
        sender_chain_key.iteration(),
        sender_chain_key.seed().to_vec(),
        state
            .signing_key_public()
            .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?,
    )
}
