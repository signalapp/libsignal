//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Models of client identity and session store behavior for protocol tests.
//!
//! These model the callbacks used by libsignal, not complete client databases.
//!
//! | Behavior | Android | iOS | Desktop |
//! | --- | --- | --- | --- |
//! | Remote receiving trust | Accept changed key | Accept changed key | Accept changed key |
//! | Outgoing identity mismatch | Return false | Callback error | Return false |
//! | Identity storage scope | Account | Account | Account |
//! | Sessions archived on identity replacement | Sibling devices | All devices | Sibling devices |
//! | Sending on a newly changed identity | Requires approval | Requires approval | Requires approval |

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use async_trait::async_trait;
use libsignal_protocol::*;

/// The client whose identity-change side effects should be simulated.
#[derive(Clone, Copy, Debug)]
pub enum ClientBehavior {
    Android,
    Ios,
    Desktop,
}

/// Session handles share the same serialized records, including writes made
/// from inside an identity callback. Loading always deserializes a fresh copy.
#[derive(Clone, Default)]
pub struct ClientSessionStore(Rc<RefCell<HashMap<ProtocolAddress, Vec<u8>>>>);

#[async_trait(?Send)]
impl SessionStore for ClientSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        self.0
            .borrow()
            .get(address)
            .map(|bytes| SessionRecord::deserialize(bytes))
            .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0
            .borrow_mut()
            .insert(address.clone(), record.serialize()?);
        Ok(())
    }
}

struct StoredIdentity {
    key: IdentityKey,
    approved: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("identityKeyMismatchForOutgoingMessage")]
struct IdentityKeyMismatch;

/// An account-wide identity store paired with the session store used by the
/// protocol operation. Changed identities require approval before sending.
pub struct ClientIdentityStore {
    behavior: ClientBehavior,
    local_address: ProtocolAddress,
    key_pair: IdentityKeyPair,
    registration_id: u32,
    identities: HashMap<String, StoredIdentity>,
    sessions: ClientSessionStore,
    save_calls: usize,
}

impl ClientIdentityStore {
    pub fn new(
        behavior: ClientBehavior,
        local_address: ProtocolAddress,
        key_pair: IdentityKeyPair,
        registration_id: u32,
        sessions: ClientSessionStore,
    ) -> Self {
        Self {
            behavior,
            local_address,
            key_pair,
            registration_id,
            sessions,
            identities: HashMap::new(),
            save_calls: 0,
        }
    }

    /// Represents user approval, or the end of a nonblocking approval interval.
    /// It never changes which key the identity store holds.
    pub fn approve_identity(&mut self, address: &ProtocolAddress) {
        self.identities
            .get_mut(address.name())
            .expect("identity exists")
            .approved = true;
    }

    pub fn save_calls(&self) -> usize {
        self.save_calls
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for ClientIdentityStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self
            .identities
            .get(address.name())
            .map(|identity| identity.key))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        key: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        if address.name() == self.local_address.name() {
            return Ok(key == self.key_pair.identity_key());
        }
        match direction {
            Direction::Receiving => Ok(true),
            Direction::Sending => match self.identities.get(address.name()) {
                Some(identity)
                    if identity.key != *key && matches!(self.behavior, ClientBehavior::Ios) =>
                {
                    // OWSIdentityManager throws for an outgoing key mismatch;
                    // the other clients return false from their trust callback.
                    Err(SignalProtocolError::ApplicationCallbackError(
                        "is_trusted_identity",
                        Box::new(IdentityKeyMismatch),
                    ))
                }
                identity => {
                    Ok(identity.is_none_or(|identity| identity.key == *key && identity.approved))
                }
            },
        }
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        key: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        self.save_calls += 1;
        let changed = match self.identities.get(address.name()) {
            Some(identity) if identity.key == *key => return Ok(IdentityChange::NewOrUnchanged),
            Some(_) => true,
            None => false,
        };
        self.identities.insert(
            address.name().to_owned(),
            StoredIdentity {
                key: *key,
                approved: !changed,
            },
        );
        if !changed {
            return Ok(IdentityChange::NewOrUnchanged);
        }

        // iOS archives all sessions for the account. Android and Desktop leave
        // this device's session for libsignal to replace, and archive siblings.
        let mut sessions = self.sessions.0.borrow_mut();
        for (peer, bytes) in sessions.iter_mut() {
            if peer.name() == address.name()
                && (matches!(self.behavior, ClientBehavior::Ios)
                    || peer.device_id() != address.device_id())
            {
                let mut session = SessionRecord::deserialize(bytes)?;
                session.archive_current_state()?;
                *bytes = session.serialize()?;
            }
        }
        Ok(IdentityChange::ReplacedExisting)
    }
}
