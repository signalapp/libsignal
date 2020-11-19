//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![deny(warnings)]

use aes_gcm_siv::Aes256GcmSiv;
use libsignal_protocol_rust::*;

#[cfg(not(any(feature = "ffi", feature = "jni")))]
compile_error!("Either feature \"ffi\" or \"jni\" must be enabled for this crate.");

#[cfg(feature = "ffi")]
#[macro_use]
mod support_ffi;
#[cfg(feature = "ffi")]
pub use support_ffi::*;

#[cfg(feature = "jni")]
#[macro_use]
mod support_jni;
#[cfg(feature = "jni")]
pub use support_jni::*;

bridge_destroy!(ProtocolAddress, ffi = address, jni = ProtocolAddress);

bridge_destroy!(PublicKey, ffi = publickey, jni = ECPublicKey);
#[cfg(not(feature = "jni"))]
bridge_deserialize!(PublicKey::deserialize, ffi = publickey);

bridge_destroy!(PrivateKey, ffi = privatekey, jni = ECPrivateKey);
bridge_deserialize!(
    PrivateKey::deserialize,
    ffi = privatekey,
    jni = ECPrivateKey
);

#[cfg(not(feature = "jni"))]
bridge_destroy!(SessionRecord);
#[cfg(not(feature = "jni"))]
bridge_deserialize!(SessionRecord::deserialize);

bridge_destroy!(Fingerprint, jni = NumericFingerprintGenerator);

bridge_destroy!(SignalMessage, ffi = message);
bridge_deserialize!(SignalMessage::try_from, ffi = message);

bridge_destroy!(PreKeySignalMessage);
bridge_deserialize!(PreKeySignalMessage::try_from);

bridge_destroy!(SenderKeyMessage);
bridge_deserialize!(SenderKeyMessage::try_from);

bridge_destroy!(SenderKeyDistributionMessage);
bridge_deserialize!(SenderKeyDistributionMessage::try_from);

bridge_destroy!(PreKeyBundle);

bridge_destroy!(SignedPreKeyRecord);
bridge_deserialize!(SignedPreKeyRecord::deserialize);

bridge_destroy!(PreKeyRecord);
bridge_deserialize!(PreKeyRecord::deserialize);

bridge_destroy!(SenderKeyName);

bridge_destroy!(SenderKeyRecord);
bridge_deserialize!(SenderKeyRecord::deserialize);

#[cfg(not(feature = "jni"))]
bridge_destroy!(CiphertextMessage);

bridge_destroy!(ServerCertificate);
bridge_deserialize!(ServerCertificate::deserialize);

bridge_destroy!(SenderCertificate);
bridge_deserialize!(SenderCertificate::deserialize);

bridge_destroy!(UnidentifiedSenderMessageContent);
bridge_deserialize!(UnidentifiedSenderMessageContent::deserialize);

#[cfg(not(feature = "ffi"))]
bridge_destroy!(UnidentifiedSenderMessage);
#[cfg(not(feature = "ffi"))]
bridge_deserialize!(UnidentifiedSenderMessage::deserialize);

#[cfg(not(feature = "ffi"))]
bridge_destroy!(SessionRecord);
#[cfg(not(feature = "ffi"))]
bridge_deserialize!(SessionRecord::deserialize);

#[cfg(not(feature = "ffi"))]
bridge_destroy!(SessionState);
#[cfg(not(feature = "ffi"))]
bridge_deserialize!(SessionState::deserialize);

bridge_destroy!(Aes256GcmSiv);
