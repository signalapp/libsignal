//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![deny(warnings)]
#![deny(unsafe_code)]

mod address;
mod consts;
mod crypto;
mod curve;
mod error;
mod fingerprint;
mod group_cipher;
mod identity_key;
mod kdf;
mod proto;
mod protocol;
mod ratchet;
mod sealed_sender;
mod sender_keys;
mod session;
mod session_cipher;
mod state;
mod storage;
mod utils;

pub use {
    address::ProtocolAddress,
    curve::{KeyPair, PrivateKey, PublicKey},
    error::SignalProtocolError,
    fingerprint::{DisplayableFingerprint, Fingerprint, ScannableFingerprint},
    group_cipher::{
        create_sender_key_distribution_message, group_decrypt, group_encrypt,
        process_sender_key_distribution_message,
    },
    identity_key::{IdentityKey, IdentityKeyPair},
    kdf::HKDF,
    protocol::{
        CiphertextMessage, CiphertextMessageType, PreKeySignalMessage,
        SenderKeyDistributionMessage, SenderKeyMessage, SignalMessage,
    },
    ratchet::{
        are_we_alice, initialize_alice_session, initialize_bob_session,
        AliceSignalProtocolParameters, BobSignalProtocolParameters, ChainKey, MessageKeys, RootKey,
    },
    sealed_sender::{SenderCertificate, ServerCertificate, UnidentifiedSenderMessageContent, UnidentifiedSenderMessage},
    sender_keys::{
        SenderChainKey, SenderKeyName, SenderKeyRecord, SenderKeyState, SenderMessageKey,
    },
    session::*,
    session_cipher::{
        message_decrypt, message_decrypt_prekey, message_decrypt_signal, message_encrypt,
        remote_registration_id, session_version,
    },
    state::{PreKeyBundle, PreKeyRecord, SessionRecord, SessionState, SignedPreKeyRecord},
    storage::{
        Context, Direction, IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore,
        InMemSenderKeyStore, InMemSessionStore, InMemSignalProtocolStore, InMemSignedPreKeyStore,
        PreKeyStore, ProtocolStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
    },
};
