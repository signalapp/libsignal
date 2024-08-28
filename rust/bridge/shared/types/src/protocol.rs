//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Will be unused when building for Node only.
#[allow(unused_imports)]
use futures_util::FutureExt;
use libsignal_protocol::*;
use static_assertions::const_assert_eq;

use crate::*;

#[allow(dead_code)]
const KYBER_KEY_TYPE: kem::KeyType = kem::KeyType::Kyber1024;

pub type KyberKeyPair = kem::KeyPair;
pub type KyberPublicKey = kem::PublicKey;
pub type KyberSecretKey = kem::SecretKey;

bridge_as_handle!(CiphertextMessage, jni = false);
bridge_as_handle!(DecryptionErrorMessage);
bridge_as_handle!(Fingerprint, jni = NumericFingerprintGenerator);
bridge_as_handle!(PlaintextContent);
bridge_as_handle!(PreKeyBundle);
bridge_as_handle!(PreKeyRecord);
bridge_as_handle!(PreKeySignalMessage);
bridge_as_handle!(PrivateKey, ffi = privatekey, jni = ECPrivateKey);
bridge_as_handle!(ProtocolAddress, ffi = address);
bridge_as_handle!(PublicKey, ffi = publickey, jni = ECPublicKey);
bridge_as_handle!(SenderCertificate);
bridge_as_handle!(SenderKeyDistributionMessage);
bridge_as_handle!(SenderKeyMessage);
bridge_as_handle!(SenderKeyRecord);
bridge_as_handle!(ServerCertificate);
bridge_as_handle!(SessionRecord, mut = true);
bridge_as_handle!(SignalMessage, ffi = message);
bridge_as_handle!(SignedPreKeyRecord);
bridge_as_handle!(KyberPreKeyRecord);
bridge_as_handle!(UnidentifiedSenderMessageContent);
bridge_as_handle!(SealedSenderDecryptionResult, ffi = false, jni = false);
bridge_as_handle!(KyberKeyPair);
bridge_as_handle!(KyberPublicKey);
bridge_as_handle!(KyberSecretKey);

pub use libsignal_protocol::Timestamp;

#[derive(Debug)]
#[repr(C)]
pub enum FfiContentHint {
    Default = 0,
    Resendable = 1,
    Implicit = 2,
}

const_assert_eq!(
    FfiContentHint::Default as u32,
    ContentHint::Default.to_u32(),
);
const_assert_eq!(
    FfiContentHint::Resendable as u32,
    ContentHint::Resendable.to_u32(),
);
const_assert_eq!(
    FfiContentHint::Implicit as u32,
    ContentHint::Implicit.to_u32()
);

#[derive(Debug)]
#[repr(C)]
pub enum FfiCiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    SenderKey = 7,
    Plaintext = 8,
}

const_assert_eq!(
    FfiCiphertextMessageType::Whisper as u8,
    CiphertextMessageType::Whisper as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::PreKey as u8,
    CiphertextMessageType::PreKey as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::SenderKey as u8,
    CiphertextMessageType::SenderKey as u8
);
const_assert_eq!(
    FfiCiphertextMessageType::Plaintext as u8,
    CiphertextMessageType::Plaintext as u8
);
