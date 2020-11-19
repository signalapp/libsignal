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

bridge_destroy!(PrivateKey, ffi = privatekey, jni = ECPrivateKey);

#[cfg(not(feature = "jni"))]
bridge_destroy!(SessionRecord);

bridge_destroy!(Fingerprint, jni = NumericFingerprintGenerator);

bridge_destroy!(SignalMessage, ffi = message);

bridge_destroy!(PreKeySignalMessage);

bridge_destroy!(SenderKeyMessage);

bridge_destroy!(SenderKeyDistributionMessage);

bridge_destroy!(PreKeyBundle);

bridge_destroy!(SignedPreKeyRecord);

bridge_destroy!(PreKeyRecord);

bridge_destroy!(SenderKeyName);

bridge_destroy!(SenderKeyRecord);

#[cfg(not(feature = "jni"))]
bridge_destroy!(CiphertextMessage);

bridge_destroy!(ServerCertificate);

bridge_destroy!(SenderCertificate);

bridge_destroy!(UnidentifiedSenderMessageContent);

#[cfg(not(feature = "ffi"))]
bridge_destroy!(UnidentifiedSenderMessage);

#[cfg(not(feature = "ffi"))]
bridge_destroy!(SessionRecord);

#[cfg(not(feature = "ffi"))]
bridge_destroy!(SessionState);

bridge_destroy!(Aes256GcmSiv);
