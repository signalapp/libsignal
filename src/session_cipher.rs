use crate::{
    IdentityKeyStore, PreKeyStore, ProtocolAddress, SessionRecord, SessionState, SessionStore,
    SignalProtocolError, SignedPreKeyStore,
};

use crate::curve;
use crate::error::Result;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use crate::ratchet::{ChainKey, MessageKeys};
use crate::session;
use crate::storage::Direction;

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use rand::{CryptoRng, Rng};

/*
* Prevent a message from jumping too far forward to avoid computation DoS.
* The specific value is arbitrary, value taking from libsignal-protocol-java
*/
const MAX_FORWARD_CHAIN_JUMPS: u32 = 2000;

pub struct SessionCipher<'a> {
    remote_address: ProtocolAddress,
    session_store: &'a mut dyn SessionStore,
    identity_store: &'a mut dyn IdentityKeyStore,
    signed_prekey_store: &'a mut dyn SignedPreKeyStore,
    pre_key_store: &'a mut dyn PreKeyStore,
}

fn aes_256_cbc_encrypt(ptext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(SignalProtocolError::InvalidCipherKeyLength(key.len()));
    }
    if iv.len() != 16 {
        return Err(SignalProtocolError::InvalidCipherNonceLength(iv.len()));
    }

    let mode = Cbc::<Aes256, Pkcs7>::new_var(key, iv)
        .map_err(|e| SignalProtocolError::InvalidArgument(format!("{}", e)))?;
    Ok(mode.encrypt_vec(&ptext))
}

fn aes_256_cbc_decrypt(ctext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(SignalProtocolError::InvalidCipherKeyLength(key.len()));
    }
    if iv.len() != 16 {
        return Err(SignalProtocolError::InvalidCipherNonceLength(iv.len()));
    }
    if ctext.len() == 0 || ctext.len() % 16 != 0 {
        return Err(SignalProtocolError::InvalidCiphertext);
    }

    let mode = Cbc::<Aes256, Pkcs7>::new_var(key, iv)
        .map_err(|e| SignalProtocolError::InvalidArgument(format!("{}", e)))?;
    Ok(mode
        .decrypt_vec(ctext)
        .map_err(|_| SignalProtocolError::InvalidCiphertext)?)
}

impl<'a> SessionCipher<'a> {
    pub fn new(
        remote_address: ProtocolAddress,
        session_store: &'a mut dyn SessionStore,
        identity_store: &'a mut dyn IdentityKeyStore,
        signed_prekey_store: &'a mut dyn SignedPreKeyStore,
        pre_key_store: &'a mut dyn PreKeyStore,
    ) -> Self {
        SessionCipher {
            remote_address,
            session_store,
            identity_store,
            signed_prekey_store,
            pre_key_store,
        }
    }

    pub fn encrypt(&mut self, ptext: &[u8]) -> Result<CiphertextMessage> {
        let mut session_record = self
            .session_store
            .load_session(&self.remote_address)?
            .ok_or(SignalProtocolError::SessionNotFound)?;
        let session_state = session_record.session_state_mut()?;

        let chain_key = session_state.get_sender_chain_key()?;

        let message_keys = chain_key.message_keys();

        let sender_ephemeral = session_state.sender_ratchet_key()?;
        let previous_counter = session_state.previous_counter()?;
        let session_version = session_state.session_version()? as u8;

        let local_identity_key = session_state.local_identity_key()?;
        let their_identity_key = session_state
            .remote_identity_key()?
            .ok_or(SignalProtocolError::InvalidSessionStructure)?;

        let ctext = aes_256_cbc_encrypt(ptext, message_keys.cipher_key(), message_keys.iv())?;

        let message = if let Some(items) = session_state.unacknowledged_pre_key_message_items()? {
            let local_registration_id = session_state.local_registration_id()?;

            let message = SignalMessage::new(
                session_version,
                message_keys.mac_key(),
                sender_ephemeral,
                chain_key.index(),
                previous_counter,
                ctext.into_boxed_slice(),
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
                ctext.into_boxed_slice(),
                &local_identity_key,
                &their_identity_key,
            )?)
        };

        session_state.set_sender_chain_key(&chain_key.next_chain_key())?;

        // XXX why is this check after everything else?!!
        if !self.identity_store.is_trusted_identity(
            &self.remote_address,
            &their_identity_key,
            Direction::Sending,
        )? {
            return Err(SignalProtocolError::UntrustedIdentity(
                self.remote_address.clone(),
            ));
        }

        // XXX this could be combined with the above call to the identity store (in a new API)
        self.identity_store
            .save_identity(&self.remote_address, &their_identity_key)?;

        self.session_store
            .store_session(&self.remote_address, &session_record)?;
        Ok(message)
    }

    pub fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        ciphertext: &CiphertextMessage,
        csprng: &mut R,
    ) -> Result<Vec<u8>> {
        match ciphertext {
            CiphertextMessage::SignalMessage(m) => self.decrypt_message(m, csprng),
            CiphertextMessage::PreKeySignalMessage(m) => self.decrypt_with_prekey(m, csprng),
            _ => Err(SignalProtocolError::InvalidArgument(
                "SessionCipher::decrypt cannot decrypt this message type".to_owned(),
            )),
        }
    }

    fn decrypt_with_prekey<R: Rng + CryptoRng>(
        &mut self,
        ciphertext: &PreKeySignalMessage,
        csprng: &mut R,
    ) -> Result<Vec<u8>> {
        let mut session_record = match self.session_store.load_session(&self.remote_address)? {
            Some(s) => s,
            None => SessionRecord::new_fresh(),
        };

        let pre_key_id = session::process_prekey(
            self.signed_prekey_store,
            self.pre_key_store,
            self.identity_store,
            &self.remote_address,
            &mut session_record,
            ciphertext,
        )?;

        let ptext =
            self.decrypt_message_with_record(&mut session_record, ciphertext.message(), csprng)?;

        self.session_store
            .store_session(&self.remote_address, &session_record)?;

        if let Some(pre_key_id) = pre_key_id {
            self.pre_key_store.remove_pre_key(pre_key_id)?;
        }

        Ok(ptext)
    }

    fn decrypt_message<R: Rng + CryptoRng>(
        &mut self,
        ciphertext: &SignalMessage,
        csprng: &mut R,
    ) -> Result<Vec<u8>> {
        let mut session_record = self
            .session_store
            .load_session(&self.remote_address)?
            .ok_or(SignalProtocolError::InternalError("SessionCipher::decrypt"))?;

        let ptext = self.decrypt_message_with_record(&mut session_record, ciphertext, csprng)?;

        // Why are we performing this check after decryption instead of before?
        let their_identity_key = session_record
            .session_state()?
            .remote_identity_key()?
            .ok_or(SignalProtocolError::InvalidSessionStructure)?;
        if !self.identity_store.is_trusted_identity(
            &self.remote_address,
            &their_identity_key,
            Direction::Receiving,
        )? {
            return Err(SignalProtocolError::UntrustedIdentity(
                self.remote_address.clone(),
            ));
        }

        self.identity_store
            .save_identity(&self.remote_address, &their_identity_key)?;

        self.session_store
            .store_session(&self.remote_address, &session_record)?;

        Ok(ptext)
    }

    fn decrypt_message_with_record<R: Rng + CryptoRng>(
        &mut self,
        record: &mut SessionRecord,
        ciphertext: &SignalMessage,
        csprng: &mut R,
    ) -> Result<Vec<u8>> {
        let mut current_state = record.session_state()?.clone();

        if let Ok(ptext) = self.decrypt_message_with_state(&mut current_state, ciphertext, csprng) {
            record.set_session_state(current_state)?; // update the state
            return Ok(ptext);
        }

        /*
        XXX Missing logic here:

                let from_old_session = for previous in record.previous_session_states()? {
                    let mut updated = previous.clone();
                    if let Ok(ptext) = self.decrypt_message_with_state(&mut updated, ciphertext) {
                        return Some((ptext, updated, previous));
                    }
                    None
                };
        */

        Err(SignalProtocolError::InternalError(
            "decrypt_message_with_record session not found",
        ))
    }

    fn decrypt_message_with_state<R: Rng + CryptoRng>(
        &mut self,
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
        let chain_key = self.get_or_create_chain_key(state, their_ephemeral, csprng)?;
        let message_keys =
            self.get_or_create_message_key(state, their_ephemeral, &chain_key, counter)?;

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

        let ptext = aes_256_cbc_decrypt(
            ciphertext.body(),
            message_keys.cipher_key(),
            message_keys.iv(),
        )?;

        state.clear_unacknowledged_pre_key_message()?;

        Ok(ptext)
    }

    pub fn remote_registration_id(&self) -> Result<u32> {
        let session_record = self
            .session_store
            .load_session(&self.remote_address)?
            .ok_or(SignalProtocolError::SessionNotFound)?;
        session_record.session_state()?.remote_registration_id()
    }

    pub fn session_version(&self) -> Result<u32> {
        let session_record = self
            .session_store
            .load_session(&self.remote_address)?
            .ok_or(SignalProtocolError::SessionNotFound)?;
        session_record.session_state()?.session_version()
    }

    fn get_or_create_chain_key<R: Rng + CryptoRng>(
        &self,
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
        let our_new_ephemeral = curve::KeyPair::new(csprng);
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
        &self,
        state: &mut SessionState,
        their_ephemeral: &curve::PublicKey,
        chain_key: &ChainKey,
        counter: u32,
    ) -> Result<MessageKeys> {
        let chain_index = chain_key.index();

        if chain_index > counter {
            if state.has_message_keys(their_ephemeral, counter)? {
                return Ok(state
                    .remove_message_keys(their_ephemeral, counter)?
                    .ok_or(SignalProtocolError::InternalError("message key not found"))?);
            } else {
                return Err(SignalProtocolError::DuplicatedMessage(chain_index, counter));
            }
        }

        assert!(chain_index <= counter);

        if counter - chain_index > MAX_FORWARD_CHAIN_JUMPS {
            return Err(SignalProtocolError::InvalidMessage(
                "message from too far into the future",
            ));
        }

        let mut chain_key = chain_key.clone();

        while chain_key.index() < counter {
            let message_keys = chain_key.message_keys();
            state.set_message_keys(their_ephemeral, &message_keys)?;
            chain_key = chain_key.next_chain_key();
        }

        state.set_receiver_chain_key(their_ephemeral, &chain_key.next_chain_key())?;
        Ok(chain_key.message_keys())
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn aes_cbc_test() {
        let key = hex::decode("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
            .unwrap();
        let iv = hex::decode("6f8a557ddc0a140c878063a6d5f31d3d").unwrap();

        let ptext = hex::decode("30736294a124482a4159").unwrap();

        let ctext = super::aes_256_cbc_encrypt(&ptext, &key, &iv).unwrap();
        assert_eq!(
            hex::encode(ctext.clone()),
            "dd3f573ab4508b9ed0e45e0baf5608f3"
        );

        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &iv).unwrap();
        assert_eq!(hex::encode(ptext), hex::encode(recovered.clone()));

        // padding is invalid:
        assert!(super::aes_256_cbc_decrypt(&recovered, &key, &iv).is_err());
        assert!(super::aes_256_cbc_decrypt(&ctext, &key, &ctext).is_err());

        // bitflip the IV to cause a change in the recovered text
        let bad_iv = hex::decode("ef8a557ddc0a140c878063a6d5f31d3d").unwrap();
        let recovered = super::aes_256_cbc_decrypt(&ctext, &key, &bad_iv).unwrap();
        assert_eq!(hex::encode(recovered), "b0736294a124482a4159");
    }
}
