//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(missing_docs)]

//! A normalized representation of an individual Signal client instance.

#[cfg(doc)]
use crate::SignalMessage;

use std::fmt;

/// The type used in memory to represent a *device*, i.e. a particular Signal client instance which
/// represents some user.
///
/// Used in [ProtocolAddress].
pub type DeviceId = u32;

/// Represents a unique Signal client instance as `(<user ID>, <device ID>)` pair.
#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProtocolAddress {
    name: String,
    device_id: DeviceId,
}

impl ProtocolAddress {
    /// Create a new address.
    ///
    /// - `name` defines a user's public identity, and therefore must be globally unique to that
    /// user.
    /// - Each Signal client instance then has its own `device_id`, which must be unique among
    ///   all clients for that user.
    ///
    ///```
    /// use libsignal_protocol::{DeviceId, ProtocolAddress};
    ///
    /// // This is a unique id for some user, typically a UUID.
    /// let user_id: String = "04899A85-4C9E-44CC-8428-A02AB69335F1".to_string();
    /// // Each client instance representing that user has a unique device id.
    /// let device_id: DeviceId = 2_u32.into();
    /// let address = ProtocolAddress::new(user_id.clone(), device_id);
    ///
    /// assert!(address.name() == &user_id);
    /// assert!(address.device_id() == device_id);
    ///```
    pub fn new(name: String, device_id: DeviceId) -> Self {
        ProtocolAddress { name, device_id }
    }

    /// A unique identifier for the target user. This is usually a UUID.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// An identifier representing a particular Signal client instance to send to.
    ///
    /// For example, if a user has set up Signal on both their phone and laptop, any [SignalMessage]
    /// sent to the user will still only go to a single device. So when a user sends a message to
    /// another user at all, they're actually sending a message to *every* device.
    #[inline]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}
