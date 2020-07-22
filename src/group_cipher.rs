use crate::crypto;
use crate::curve;
use crate::error::Result;
use crate::protocol::{SenderKeyDistributionMessage, SenderKeyMessage};
use crate::sender_keys::{SenderKeyRecord, SenderKeyState, SenderMessageKey};
use crate::{SenderKeyName, SenderKeyStore, SignalProtocolError};

use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

pub fn group_encrypt<R: Rng + CryptoRng>(
    sender_key_store: &mut dyn SenderKeyStore,
    sender_key_id: &SenderKeyName,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<Vec<u8>> {
    let mut record = sender_key_store
        .load_sender_key(&sender_key_id)?
        .ok_or(SignalProtocolError::InvalidSenderKeyId)?;

    let sender_key_state = record.sender_key_state()?;

    let sender_key = sender_key_state.sender_chain_key()?.sender_message_key()?;

    let ciphertext =
        crypto::aes_256_cbc_encrypt(plaintext, &sender_key.cipher_key()?, &sender_key.iv()?)?;

    let signing_key = sender_key_state
        .signing_key_private()?
        .ok_or(SignalProtocolError::SenderKeySigningKeyMissing)?;

    let skm = SenderKeyMessage::new(
        sender_key_state.sender_key_id()?,
        sender_key.iteration()?,
        ciphertext.into_boxed_slice(),
        csprng,
        &signing_key,
    )?;

    sender_key_state.set_sender_chain_key(sender_key_state.sender_chain_key()?.next()?)?;

    sender_key_store.store_sender_key(sender_key_id, &record)?;

    Ok(skm.serialized().to_vec())
}

fn get_sender_key(state: &mut SenderKeyState, iteration: u32) -> Result<SenderMessageKey> {
    let sender_chain_key = state.sender_chain_key()?;

    if sender_chain_key.iteration()? > iteration {
        if let Some(smk) = state.remove_sender_message_key(iteration)? {
            return Ok(smk);
        } else {
            return Err(SignalProtocolError::DuplicatedMessage(
                sender_chain_key.iteration()?,
                iteration,
            ));
        }
    }

    if iteration - sender_chain_key.iteration()? > 2000 {
        return Err(SignalProtocolError::InvalidMessage(
            "message from too far into the future",
        ));
    }

    let mut sender_chain_key = sender_chain_key.clone();

    while sender_chain_key.iteration()? < iteration {
        state.add_sender_message_key(&sender_chain_key.sender_message_key()?)?;
        sender_chain_key = sender_chain_key.next()?;
    }

    state.set_sender_chain_key(sender_chain_key.next()?)?;
    Ok(sender_chain_key.sender_message_key()?)
}

pub fn group_decrypt(
    skm_bytes: &[u8],
    sender_key_store: &mut dyn SenderKeyStore,
    sender_key_id: &SenderKeyName,
) -> Result<Vec<u8>> {
    let mut record = sender_key_store
        .load_sender_key(&sender_key_id)?
        .ok_or(SignalProtocolError::InvalidSenderKeyId)?;

    let skm = SenderKeyMessage::try_from(skm_bytes)?;

    let mut sender_key_state = record.sender_key_state_for_keyid(skm.key_id())?;

    let signing_key = sender_key_state.signing_key_public()?;
    if !skm.verify_signature(&signing_key)? {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let sender_key = get_sender_key(&mut sender_key_state, skm.iteration())?;

    let plaintext = crypto::aes_256_cbc_decrypt(
        skm.ciphertext(),
        &sender_key.cipher_key()?,
        &sender_key.iv()?,
    )?;

    sender_key_store.store_sender_key(sender_key_id, &record)?;

    Ok(plaintext)
}

pub fn process_sender_key_distribution_message(
    sender_key_name: &SenderKeyName,
    skdm: &SenderKeyDistributionMessage,
    sender_key_store: &mut dyn SenderKeyStore,
) -> Result<()> {
    let mut sender_key_record = sender_key_store
        .load_sender_key(sender_key_name)?
        .unwrap_or(SenderKeyRecord::new_empty());

    sender_key_record.add_sender_key_state(
        skdm.id()?,
        skdm.iteration()?,
        skdm.chain_key()?,
        *skdm.signing_key()?,
        None,
    )?;
    sender_key_store.store_sender_key(sender_key_name, &sender_key_record)?;
    Ok(())
}

pub fn create_sender_key_distribution_message<R: Rng + CryptoRng>(
    sender_key_name: &SenderKeyName,
    sender_key_store: &mut dyn SenderKeyStore,
    csprng: &mut R,
) -> Result<SenderKeyDistributionMessage> {
    let mut sender_key_record = match sender_key_store.load_sender_key(sender_key_name)? {
        None => {
            let mut sender_key_record = SenderKeyRecord::new_empty();

            let sender_key_id: u32 = csprng.gen();
            let iteration = 0;
            let sender_key: [u8; 32] = csprng.gen();
            let signing_key = curve::KeyPair::new(csprng);
            sender_key_record.set_sender_key_state(
                sender_key_id,
                iteration,
                &sender_key,
                signing_key.public_key,
                Some(signing_key.private_key),
            )?;
            sender_key_store.store_sender_key(sender_key_name, &sender_key_record)?;
            sender_key_record
        }
        Some(skr) => skr,
    };

    let state = sender_key_record.sender_key_state()?;
    let sender_chain_key = state.sender_chain_key()?;

    SenderKeyDistributionMessage::new(
        state.sender_key_id()?,
        sender_chain_key.iteration()?,
        &sender_chain_key.seed()?,
        state.signing_key_public()?,
    )
}
