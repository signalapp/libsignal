use crate::{IdentityKeyStore,
            PreKeyStore,
            SignedPreKeyStore,
            SessionStore,
            ProtocolAddress,
            SessionRecord,
            SignalProtocolError};

use crate::curve;
use crate::ratchet;
use crate::error::Result;
use crate::protocol::{PreKeySignalMessage};
use crate::storage::Direction;
use crate::state::{PreKeyId, PreKeyBundle};
use crate::ratchet::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use rand::{Rng, CryptoRng};

pub struct SessionBuilder<'a> {
    remote_address: ProtocolAddress,
    session_store: &'a mut dyn SessionStore,
    identity_store: &'a mut dyn IdentityKeyStore,
    signed_prekey_store: &'a mut dyn SignedPreKeyStore,
    pre_key_store: &'a mut dyn PreKeyStore,
}

impl<'a> SessionBuilder<'a> {

    pub fn new(remote_address: ProtocolAddress,
               session_store: &'a mut dyn SessionStore,
               identity_store: &'a mut dyn IdentityKeyStore,
               signed_prekey_store: &'a mut dyn SignedPreKeyStore,
               pre_key_store: &'a mut dyn PreKeyStore) -> Self {
        SessionBuilder {
            remote_address,
            session_store,
            identity_store,
            signed_prekey_store,
            pre_key_store
        }
    }

    pub fn process_prekey(&mut self, session_record: &mut SessionRecord, message: &PreKeySignalMessage) -> Result<Option<PreKeyId>> {
        let their_identity_key = message.identity_key();

        if !self.identity_store.is_trusted_identity(&self.remote_address, their_identity_key, Direction::Receiving)? {
            return Err(SignalProtocolError::UntrustedIdentity(self.remote_address.clone()));
        }

        let unsigned_pre_key_id = self.process_prekey_v3(session_record, message)?;

        self.identity_store.save_identity(&self.remote_address, their_identity_key)?;

        Ok(unsigned_pre_key_id)
    }

    fn process_prekey_v3(&mut self, session_record: &mut SessionRecord, message: &PreKeySignalMessage) -> Result<Option<PreKeyId>> {
        if session_record.has_session_state(message.message_version() as u32, &message.base_key().serialize())? {
            // We've already setup a session for this V3 message, letting bundled message fall through
            return Ok(None);
        }

        let our_signed_pre_key_pair = self.signed_prekey_store.get_signed_pre_key(message.signed_pre_key_id())?.key_pair()?;

        let our_one_time_pre_key_pair = if let Some(pre_key_id) = message.pre_key_id() {
            Some(self.pre_key_store.get_pre_key(pre_key_id)?.key_pair()?)
        } else {
            None
        };

        let parameters = BobSignalProtocolParameters::new(
            self.identity_store.get_identity_key_pair()?,
            our_signed_pre_key_pair, // signed pre key
            our_one_time_pre_key_pair,
            our_signed_pre_key_pair, // ratchet key
            message.identity_key().clone(),
            *message.base_key());

        session_record.archive_current_state()?;

        let mut new_session = ratchet::initialize_bob_session(&parameters)?;

        new_session.set_local_registration_id(self.identity_store.get_local_registration_id()?)?;
        new_session.set_remote_registration_id(message.registration_id())?;
        new_session.set_alice_base_key(&message.base_key().serialize())?;

        session_record.promote_state(new_session)?;

        Ok(message.pre_key_id())
    }

    fn process_prekey_bundle<R: Rng + CryptoRng>(&mut self, bundle: &PreKeyBundle, mut csprng: &mut R) -> Result<()> {
        let their_identity_key = bundle.identity_key()?;

        if !self.identity_store.is_trusted_identity(&self.remote_address, their_identity_key, Direction::Sending)? {
            return Err(SignalProtocolError::UntrustedIdentity(self.remote_address.clone()));
        }

        if !curve::verify_signature(their_identity_key.public_key(),
                                    &bundle.signed_pre_key_public()?.serialize(),
                                    bundle.signed_pre_key_signature()?)? {
            return Err(SignalProtocolError::SignatureValidationFailed);
        }

        let mut session_record = self.session_store.load_session(&self.remote_address)?.unwrap_or(SessionRecord::new_fresh());

        let our_base_key_pair = curve::KeyPair::new(&mut csprng);
        let their_signed_prekey = bundle.signed_pre_key_public()?;

        let their_one_time_prekey = bundle.pre_key_public()?;
        let their_one_time_prekey_id = bundle.pre_key_id()?;

        let our_identity_key_pair = self.identity_store.get_identity_key_pair()?;

        let parameters = AliceSignalProtocolParameters::new(
            our_identity_key_pair,
            our_base_key_pair,
            *their_identity_key,
            *their_signed_prekey,
            *their_one_time_prekey,
            *their_signed_prekey);

        let mut session = ratchet::initialize_alice_session(&parameters, csprng)?;

        session.set_unacknowledged_pre_key_message(their_one_time_prekey_id,
                                                   bundle.signed_pre_key_id()?,
                                                   &our_base_key_pair.public_key)?;

        session.set_local_registration_id(self.identity_store.get_local_registration_id()?)?;
        session.set_remote_registration_id(bundle.registration_id()?)?;
        session.set_alice_base_key(&our_base_key_pair.public_key.serialize())?;

        self.identity_store.save_identity(&self.remote_address, their_identity_key)?;

        session_record.promote_state(session)?;

        self.session_store.store_session(&self.remote_address, &session_record)?;

        Ok(())
    }
}
