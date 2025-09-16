//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Traits defining several stores used throughout the Signal Protocol.

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::Result;
use crate::sender_keys::SenderKeyRecord;
use crate::state::{
    KyberPreKeyId, KyberPreKeyRecord, PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId,
    SignedPreKeyRecord,
};
use crate::{IdentityKey, IdentityKeyPair, ProtocolAddress, PublicKey};

// TODO: consider moving this enum into utils.rs?
/// Each Signal message can be considered to have exactly two participants, a sender and receiver.
///
/// [IdentityKeyStore::is_trusted_identity] uses this to ensure the identity provided is configured
/// for the appropriate role.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    /// We are in the context of sending a message.
    Sending,
    /// We are in the context of receiving a message.
    Receiving,
}

/// The result of saving a new identity key for a protocol address.
#[derive(Copy, Clone, Debug, Eq, PartialEq, derive_more::TryFrom)]
#[repr(C)]
#[try_from(repr)]
pub enum IdentityChange {
    /// The protocol address didn't have an identity key or had the same key.
    NewOrUnchanged,
    /// The new identity key replaced a different key for the protocol address.
    ReplacedExisting,
}

/// Interface defining the identity store, which may be in-memory, on-disk, etc.
///
/// Signal clients usually use the identity store in a [TOFU] manner, but this is not required.
///
/// [TOFU]: https://en.wikipedia.org/wiki/Trust_on_first_use
#[async_trait(?Send)]
pub trait IdentityKeyStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair>;

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// may be the same, but the store registration id returned by this method should
    /// be regenerated.
    async fn get_local_registration_id(&self) -> Result<u32>;

    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange>;

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool>;

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>>;
}

/// Interface for storing pre-keys downloaded from a server.
#[async_trait(?Send)]
pub trait PreKeyStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord>;

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()>;

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()>;
}

/// Interface for storing signed pre-keys downloaded from a server.
#[async_trait(?Send)]
pub trait SignedPreKeyStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord>;

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()>;
}

/// Interface for storing signed Kyber pre-keys downloaded from a server.
///
/// NB: libsignal makes no distinction between one-time and last-resort pre-keys.
#[async_trait(?Send)]
pub trait KyberPreKeyStore {
    /// Look up the signed kyber pre-key corresponding to `kyber_prekey_id`.
    async fn get_kyber_pre_key(&self, kyber_prekey_id: KyberPreKeyId) -> Result<KyberPreKeyRecord>;

    /// Set the entry for `kyber_prekey_id` to the value of `record`.
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()>;

    /// Mark the entry for `kyber_prekey_id` as "used".
    ///
    /// A one-time Kyber pre-key should be deleted after this point. A last-resort pre-key should
    /// not immediately be deleted, but should check whether the same combination of pre-keys was
    /// used with the given base key before, and produce an error if so.
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<()>;
}

/// Interface for a Signal client instance to store a session associated with another particular
/// separate Signal client instance.
///
/// This [SessionRecord] object between a pair of Signal clients is used to drive the state for the
/// forward-secret message chain in the [Double Ratchet] protocol.
///
/// [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/
#[async_trait(?Send)]
pub trait SessionStore {
    /// Look up the session corresponding to `address`.
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>>;

    /// Set the entry for `address` to the value of `record`.
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<()>;
}

/// Interface for storing sender key records, allowing multiple keys per user.
#[async_trait(?Send)]
pub trait SenderKeyStore {
    /// Assign `record` to the entry for `(sender, distribution_id)`.
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        // TODO: pass this by value!
        record: &SenderKeyRecord,
    ) -> Result<()>;

    /// Look up the entry corresponding to `(sender, distribution_id)`.
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>>;
}

/// Mixes in all the store interfaces defined in this module.
pub trait ProtocolStore:
    SessionStore + PreKeyStore + SignedPreKeyStore + KyberPreKeyStore + IdentityKeyStore
{
}

impl IdentityChange {
    /// Convenience constructor from a boolean `changed` flag.
    ///
    /// Returns [`IdentityChange::ReplacedExisting`] if `changed` is `true`,
    /// otherwise [`IdentityChange::NewOrUnchanged`].
    pub fn from_changed(changed: bool) -> Self {
        if changed {
            Self::ReplacedExisting
        } else {
            Self::NewOrUnchanged
        }
    }
}
