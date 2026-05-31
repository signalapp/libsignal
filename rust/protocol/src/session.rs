//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use rand::{CryptoRng, Rng};

use crate::protocol::CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION;
use crate::ratchet::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::state::GenericSignedPreKey;
use crate::{
    CiphertextMessageType, Direction, IdentityKey, IdentityKeyStore, KeyPair, KyberPreKeyId,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeySignalMessage, PreKeyStore, ProtocolAddress,
    Result, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyStore,
    ratchet
};

use std::fs;

pub struct PreKeysUsed {
    pub one_time_ec_pre_key_id: Option<PreKeyId>,
    pub signed_ec_pre_key_id: SignedPreKeyId,
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
}

/// Expected [`IdentityKeyStore`] change when [`process_prekey`] succeeds.
///
/// This represents a deferred action. Assuming later operations succeed, the
/// caller of `process_prekey` should apply this to the `IdentityKeyStore` that
/// was provided.
#[must_use]
pub struct IdentityToSave<'a> {
    pub remote_address: &'a ProtocolAddress,
    pub their_identity_key: &'a IdentityKey,
}

/*
These functions are on SessionBuilder in Java

However using SessionBuilder + SessionCipher at the same time causes
&mut sharing issues. And as SessionBuilder has no actual state beyond
its reference to the various data stores, instead the functions are
free standing.
 */


// Bob's X3DH Receive function for Alice's first message
// Paper: Receive(iskr, str, ipks, t, p)
pub async fn process_prekey<'a>(
    message: &'a PreKeySignalMessage,       // Alice's first message, params defined in protocol.rs
                                            // Paper: corresponds to message with (ipks, t, p)
                                            // Defined in protocol.rs
    remote_address: &'a ProtocolAddress,    // Logical identifier for Alice
    session_record: &mut SessionRecord,     // Bob's local session state w/ Alice. Defined in state.session.rs
    identity_store: &dyn IdentityKeyStore,  
    
    pre_key_store: &dyn PreKeyStore,                // Holds Bob's one-time EC prekeys (OPK)
    signed_prekey_store: &dyn SignedPreKeyStore,    // Holds Bob's signed EC prekeys (SPK)
    kyber_prekey_store: &dyn KyberPreKeyStore,      // Holds Bob's PQ Kyber prekeys
                                                    // Defined across state/, storage/, kem.rs
                                                    // Paper: iskr, str     
) -> Result<(Option<PreKeysUsed>, IdentityToSave<'a>)> {
    let their_identity_key = message.identity_key();    // Extract Alice's identity public key ipks

    if !identity_store  // TOFU stuff
        .is_trusted_identity(remote_address, their_identity_key, Direction::Receiving)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    let pre_keys_used = process_prekey_impl(    // Splits up logic to avoid errors?
        message,
        remote_address,
        session_record,
        signed_prekey_store,
        kyber_prekey_store,
        pre_key_store,
        identity_store,
    )
    .await?;

    let identity_to_save = IdentityToSave {     // Save identity after successful session creation
        remote_address,
        their_identity_key,
    };

    Ok((pre_keys_used, identity_to_save))   // Caller gets prekeys consumed & identity to be saved
}

// Bob receives initial PreKey message from Alice
async fn process_prekey_impl(
    message: &PreKeySignalMessage,  // Alice's initial prekey message (ephemeral keys, signed prekey IDs, etc.)
    remote_address: &ProtocolAddress,   // Alice's address
    session_record: &mut SessionRecord, // Bob's session storage for this contact
    
    signed_prekey_store: &dyn SignedPreKeyStore,    // Same as prev function
    kyber_prekey_store: &dyn KyberPreKeyStore,
    pre_key_store: &dyn PreKeyStore,
    
    identity_store: &dyn IdentityKeyStore,  // Bob's long-term identity keys
) -> Result<Option<PreKeysUsed>> {
    if session_record.promote_matching_session(
        message.message_version() as u32,
        &message.base_key().serialize(),    // base_key = Alice's DH key
    )? {
        // We've already set up a session for this message, we can exit early.
        return Ok(None);
    }

    // Check this *after* looking for an existing session; since we have already performed XDH for
    // such a session, enforcing PQXDH *now* would be silly.
    if message.message_version() == CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION { // References protocol.rs
        // Specifically return InvalidMessage here rather than LegacyCiphertextVersion; the Signal
        // Android app treats LegacyCiphertextVersion as a structural issue rather than a retryable
        // one, and won't cause the sender and receiver to move over to a PQXDH session.
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::PreKey,
            "X3DH no longer supported",
        ));
    }

    let our_signed_pre_key_pair = signed_prekey_store   // Retrieve Bob's signed prekey
                                                        // Paper: prekr (?) 
        .get_signed_pre_key(message.signed_pre_key_id())
        .await?
        .key_pair()?;

    // Retrieve Bob's Kyber prekey (post-quantum)
    let our_kyber_pre_key_pair = if let Some(kyber_pre_key_id) = message.kyber_pre_key_id() {  
        kyber_prekey_store
            .get_kyber_pre_key(kyber_pre_key_id) // Defined in protocol.rs
            .await?
            .key_pair()?
    } else {
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::PreKey,
            "missing pq pre-key ID",
        ));
    };
    
    // Extract Kyber ciphertext from Alice
    // Alice encrypted a secret w/ Bob's Kyber public prekey
    // Paper: PQ equivalent of DH key exchange
    let kyber_ciphertext =
        message
            .kyber_ciphertext()
            .ok_or(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "missing pq ciphertext",
            ))?;

    // Optional one-time prekey from Alice
    let our_one_time_pre_key_pair = if let Some(pre_key_id) = message.pre_key_id() {
        log::info!("processing PreKey message from {remote_address}");
        Some(pre_key_store.get_pre_key(pre_key_id).await?.key_pair()?)
    } else {
        log::warn!("processing PreKey message from {remote_address} which had no one-time prekey");
        None
    };

    log::info!("going to try writing to desktop");
    let pvrf_ciphertext = message.pvrf_ciphertext();

    let parameters = BobSignalProtocolParameters::new(
        identity_store.get_identity_key_pair().await?,  // ipkr
        our_signed_pre_key_pair, // signed pre key
        our_one_time_pre_key_pair,
        our_signed_pre_key_pair, // ratchet key (for DH ratchet)
        our_kyber_pre_key_pair,
        *message.identity_key(), // Alice's ipks
        *message.base_key(),     // Alice's ephemeral base key
        kyber_ciphertext,        // Alice's Kyber ciphertext 
        pvrf_ciphertext
    );

    let mut new_session = ratchet::initialize_bob_session(&parameters)?;    // Defined in ratchet.rs

    // Bob & Alice's device IDs
    new_session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    new_session.set_remote_registration_id(message.registration_id());

    // Store session state
    session_record.promote_state(new_session);

    let pre_keys_used = PreKeysUsed {
        one_time_ec_pre_key_id: message.pre_key_id(),
        signed_ec_pre_key_id: message.signed_pre_key_id(),
        kyber_pre_key_id: message.kyber_pre_key_id(),
    };
    Ok(Some(pre_keys_used)) // Return IDs of prekeys consumed this session (remove one-times after use)
}

// Alice receives Bob's prekey bundle and sets up session for first message
pub async fn process_prekey_bundle<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,   // Bob's address
    session_store: &mut dyn SessionStore,   // Alice's session storafe
    identity_store: &mut dyn IdentityKeyStore,  // Alice's identity keys
    bundle: &PreKeyBundle,  // Bob's prekey bundle (SPK, OPK, PQ PK)
    now: SystemTime,
    mut csprng: &mut R, // Cryptographically secure RNG for ephemeral key generation
) -> Result<()> {
    let their_identity_key = bundle.identity_key()?; // Retrive Bob's long-term identity key (ipkr)

    if !identity_store  // Check if Bob's identity is trustworthy (MITM protection)
        .is_trusted_identity(remote_address, their_identity_key, Direction::Sending)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    // Verify Bob's SPK and Kyber PK w/ Bob's identity key (ipkr)
    if !their_identity_key.public_key().verify_signature(
        &bundle.signed_pre_key_public()?.serialize(),
        bundle.signed_pre_key_signature()?,
    ) {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    if !their_identity_key.public_key().verify_signature(
        &bundle.kyber_pre_key_public()?.serialize(),
        bundle.kyber_pre_key_signature()?,
    ) {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    // Load/Create Alice's session record
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    let our_base_key_pair = KeyPair::generate(&mut csprng); // Generates Alice's ephemeral DH key (base key)
    
    // Extract all of Bob's prekeys from bundle
    let their_signed_prekey = bundle.signed_pre_key_public()?;
    let their_kyber_prekey = bundle.kyber_pre_key_public()?;
    let their_one_time_prekey_id = bundle.pre_key_id()?;

    let our_identity_key_pair = identity_store.get_identity_key_pair().await?;  // Retrieve Alice's identity key (ipks)

    let mut parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,  // our = Alice/sender
        our_base_key_pair,
        *their_identity_key,    // their = Bob/receiver
        their_signed_prekey,
        their_signed_prekey,
        their_kyber_prekey.clone(),
    );
    if let Some(key) = bundle.pre_key_public()? {
        parameters.set_their_one_time_pre_key(key);
    }

    // Defined in ratchet.rs
    let mut session = ratchet::initialize_alice_session(&parameters, csprng)?;  // Compute shared secrets w/ X3DH and PQ Kyber keys

    // Debugging
    log::info!(
        "set_unacknowledged_pre_key_message for: {} with preKeyId: {}",
        remote_address,
        their_one_time_prekey_id.map_or_else(|| "<none>".to_string(), |id| id.to_string())
    );

    // Mark prekeys Alice has used but Bob has not acknowledged
    session.set_unacknowledged_pre_key_message(
        their_one_time_prekey_id,
        bundle.signed_pre_key_id()?,
        &our_base_key_pair.public_key,
        now,
    );
    session.set_unacknowledged_kyber_pre_key_id(bundle.kyber_pre_key_id()?);

    // Device IDs
    session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    session.set_remote_registration_id(bundle.registration_id()?);

    // Remember Bob's identity
    identity_store
        .save_identity(remote_address, their_identity_key)
        .await?;

    // Save session into Alice's session store
    session_record.promote_state(session);

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(())
}
