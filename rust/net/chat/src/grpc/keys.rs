//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::convert::Infallible;

use itertools::Itertools as _;
use libsignal_core::ServiceIdKind;
use libsignal_net_grpc::proto::chat::common::{
    EcPreKey as EcPreKeyProto, EcSignedPreKey as EcSignedPreKeyProto, IdentityType,
    KemSignedPreKey as KemPreKeyProto,
};
use libsignal_net_grpc::proto::chat::keys::keys_client::KeysClient;
use libsignal_net_grpc::proto::chat::keys::{
    GetPreKeyCountRequest, GetPreKeyCountResponse, SetEcSignedPreKeyRequest,
    SetKemLastResortPreKeyRequest, SetOneTimeEcPreKeysRequest, SetOneTimeKemSignedPreKeysRequest,
    SetPreKeyResponse,
};
use libsignal_protocol::{KyberPreKeyId, PreKeyId, PublicKey, SignedPreKeyId, kem};

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, GrpcTestCase, log_and_send};
use crate::logging::Redact;

impl std::fmt::Display for Redact<GetPreKeyCountRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GetPreKeyCountRequest {}) = self;
        f.debug_struct("GetPreKeyCountRequest").finish()
    }
}

/// Approximate counts of the one-time pre-keys stored for the authenticated
/// device, broken down by identity (ACI/PNI) and key kind (EC/KEM).
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct PreKeyCounts {
    /// The approximate number of one-time EC pre-keys stored for the
    /// authenticated device and associated with the caller's ACI.
    pub aci_ec_pre_key_count: u32,
    /// The approximate number of one-time KEM pre-keys stored for the
    /// authenticated device and associated with the caller's ACI.
    pub aci_kem_pre_key_count: u32,
    /// The approximate number of one-time EC pre-keys stored for the
    /// authenticated device and associated with the caller's PNI.
    pub pni_ec_pre_key_count: u32,
    /// The approximate number of one-time KEM pre-keys stored for the
    /// authenticated device and associated with the caller's PNI.
    pub pni_kem_pre_key_count: u32,
}

/// A one-time elliptic-curve pre-key, as uploaded to the server.
///
/// This is only the public half of the key; the private half never leaves the
/// client.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct PublicEcPreKey<'a> {
    /// A locally-unique identifier for this key, which peers using this key to
    /// encrypt messages will provide so the private key can be looked up.
    pub key_id: PreKeyId,
    /// The public key.
    pub public_key: &'a PublicKey,
}

impl From<PublicEcPreKey<'_>> for EcPreKeyProto {
    fn from(value: PublicEcPreKey<'_>) -> Self {
        Self {
            // The server's limits on pre-key IDs are far below i32::MAX, so
            // anything out of range is a programmer error on the client side.
            key_id: i32::try_from(u32::from(value.key_id)).expect("pre-key IDs fit in i32"),
            public_key: value.public_key.serialize().into_vec(),
        }
    }
}

/// A signed elliptic-curve pre-key, as uploaded to the server.
///
/// This is only the public half of the key; the private half never leaves the
/// client.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct PublicSignedEcPreKey<'a> {
    /// A locally-unique identifier for this key, which peers using this key to
    /// encrypt messages will provide so the private key can be looked up.
    pub key_id: SignedPreKeyId,
    /// The public key.
    pub public_key: &'a PublicKey,
    /// The signature.
    pub signature: Cow<'a, [u8]>,
}

impl From<PublicSignedEcPreKey<'_>> for EcSignedPreKeyProto {
    fn from(value: PublicSignedEcPreKey<'_>) -> Self {
        Self {
            // The server's limits on pre-key IDs are far below i32::MAX, so
            // anything out of range is a programmer error on the client side.
            key_id: i32::try_from(u32::from(value.key_id)).expect("pre-key IDs fit in i32"),
            public_key: value.public_key.serialize().into_vec(),
            signature: value.signature.into_owned(),
        }
    }
}

/// A KEM pre-key (one-time or last-resort), as uploaded to the server.
///
/// This is only the public half of the key; the private half never leaves the client.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct PublicKemPreKey<'a> {
    /// A locally-unique identifier for this key, which peers using this key to
    /// encrypt messages will provide so the private key can be looked up.
    pub key_id: KyberPreKeyId,
    /// The public key.
    pub public_key: &'a kem::PublicKey,
    /// The signature.
    pub signature: Cow<'a, [u8]>,
}

impl From<PublicKemPreKey<'_>> for KemPreKeyProto {
    fn from(value: PublicKemPreKey<'_>) -> Self {
        Self {
            // The server's limits on pre-key IDs are far below i32::MAX, so
            // anything out of range is a programmer error on the client side.
            key_id: i32::try_from(u32::from(value.key_id)).expect("pre-key IDs fit in i32"),
            public_key: value.public_key.serialize().into_vec(),
            signature: value.signature.into_owned(),
        }
    }
}

impl std::fmt::Display for Redact<SetOneTimeEcPreKeysRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetOneTimeEcPreKeysRequest {
            identity_type,
            pre_keys,
        }) = self;
        f.debug_struct("SetOneTimeEcPreKeysRequest")
            .field("identity_type", identity_type)
            .field("pre_keys_len", &pre_keys.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<SetOneTimeKemSignedPreKeysRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetOneTimeKemSignedPreKeysRequest {
            identity_type,
            pre_keys,
        }) = self;
        f.debug_struct("SetOneTimeKemSignedPreKeysRequest")
            .field("identity_type", identity_type)
            .field("pre_keys_len", &pre_keys.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<SetEcSignedPreKeyRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetEcSignedPreKeyRequest {
            identity_type,
            signed_pre_key: _,
        }) = self;
        f.debug_struct("SetEcSignedPreKeyRequest")
            .field("identity_type", identity_type)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for Redact<SetKemLastResortPreKeyRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetKemLastResortPreKeyRequest {
            identity_type,
            signed_pre_key: _,
        }) = self;
        f.debug_struct("SetKemLastResortPreKeyRequest")
            .field("identity_type", identity_type)
            .finish_non_exhaustive()
    }
}

impl<T: GrpcServiceProvider> Auth<T> {
    /// Retrieves an approximate count of the number of the various kinds of
    /// one-time pre-keys stored for the authenticated device.
    pub async fn get_pre_key_count(&self) -> Result<PreKeyCounts, RequestError<Infallible>> {
        let mut client = KeysClient::new(self.0.service());
        let request = GetPreKeyCountRequest {};
        let desc = Redact(&request).to_string();
        let GetPreKeyCountResponse {
            aci_ec_pre_key_count,
            aci_kem_pre_key_count,
            pni_ec_pre_key_count,
            pni_kem_pre_key_count,
        } = log_and_send(Self::LOG_TAG, &desc, || client.get_pre_key_count(request))
            .await?
            .into_inner();
        Ok(PreKeyCounts {
            aci_ec_pre_key_count,
            aci_kem_pre_key_count,
            pni_ec_pre_key_count,
            pni_kem_pre_key_count,
        })
    }

    /// Uploads a new set of one-time EC pre-keys for the authenticated device,
    /// clearing any previously-stored one-time EC pre-keys for `identity`.
    ///
    /// `pre_keys` must contain between 1 and 100 keys.
    pub async fn set_one_time_ec_pre_keys(
        &self,
        identity: ServiceIdKind,
        pre_keys: impl IntoIterator<Item = PublicEcPreKey<'_>>,
    ) -> Result<(), RequestError<Infallible>> {
        let pre_keys = pre_keys.into_iter().map(EcPreKeyProto::from).collect_vec();
        assert!(!pre_keys.is_empty(), "cannot upload 0 pre-keys");
        let mut client = KeysClient::new(self.0.service());
        let request = SetOneTimeEcPreKeysRequest {
            identity_type: match identity {
                ServiceIdKind::Aci => IdentityType::Aci,
                ServiceIdKind::Pni => IdentityType::Pni,
            }
            .into(),
            pre_keys,
        };
        let desc = Redact(&request).to_string();
        let SetPreKeyResponse {} = log_and_send(Self::LOG_TAG, &desc, || {
            client.set_one_time_ec_pre_keys(request)
        })
        .await?
        .into_inner();
        Ok(())
    }

    /// Uploads a new set of one-time KEM pre-keys for the authenticated device,
    /// clearing any previously-stored one-time KEM pre-keys for `identity`.
    ///
    /// `pre_keys` must contain between 1 and 100 keys.
    pub async fn set_one_time_kem_pre_keys(
        &self,
        identity: ServiceIdKind,
        pre_keys: impl IntoIterator<Item = PublicKemPreKey<'_>>,
    ) -> Result<(), RequestError<Infallible>> {
        let pre_keys = pre_keys.into_iter().map(KemPreKeyProto::from).collect_vec();
        assert!(!pre_keys.is_empty(), "cannot upload 0 pre-keys");
        let mut client = KeysClient::new(self.0.service());
        let request = SetOneTimeKemSignedPreKeysRequest {
            identity_type: match identity {
                ServiceIdKind::Aci => IdentityType::Aci,
                ServiceIdKind::Pni => IdentityType::Pni,
            }
            .into(),
            pre_keys,
        };
        let desc = Redact(&request).to_string();
        let SetPreKeyResponse {} = log_and_send(Self::LOG_TAG, &desc, || {
            client.set_one_time_kem_signed_pre_keys(request)
        })
        .await?
        .into_inner();
        Ok(())
    }

    /// Uploads a new signed EC pre-key for the authenticated device,
    /// clearing any previously-stored signed EC pre-key for `identity`.
    pub async fn set_signed_ec_pre_key(
        &self,
        identity: ServiceIdKind,
        pre_key: PublicSignedEcPreKey<'_>,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = KeysClient::new(self.0.service());
        let request = SetEcSignedPreKeyRequest {
            identity_type: match identity {
                ServiceIdKind::Aci => IdentityType::Aci,
                ServiceIdKind::Pni => IdentityType::Pni,
            }
            .into(),
            signed_pre_key: Some(pre_key.into()),
        };
        let desc = Redact(&request).to_string();
        let SetPreKeyResponse {} = log_and_send(Self::LOG_TAG, &desc, || {
            client.set_ec_signed_pre_key(request)
        })
        .await?
        .into_inner();
        Ok(())
    }

    /// Uploads a new last-resort KEM pre-key for the authenticated device,
    /// clearing any previously-stored last-resort KEM pre-key for `identity`.
    pub async fn set_last_resort_kem_pre_key(
        &self,
        identity: ServiceIdKind,
        pre_key: PublicKemPreKey<'_>,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = KeysClient::new(self.0.service());
        let request = SetKemLastResortPreKeyRequest {
            identity_type: match identity {
                ServiceIdKind::Aci => IdentityType::Aci,
                ServiceIdKind::Pni => IdentityType::Pni,
            }
            .into(),
            signed_pre_key: Some(pre_key.into()),
        };
        let desc = Redact(&request).to_string();
        let SetPreKeyResponse {} = log_and_send(Self::LOG_TAG, &desc, || {
            client.set_kem_last_resort_pre_key(request)
        })
        .await?
        .into_inner();
        Ok(())
    }
}

// Not cfg(test) so it can be accessed via bridging tests.
// These tests will get pruned via LTO tree shaking.
pub mod test_cases {
    use super::*;

    pub type GetPreKeyCountArgs = ();
    pub type GetPreKeyCountOut = PreKeyCounts;
    pub fn get_pre_key_count_test_cases() -> Vec<
        GrpcTestCase<
            GetPreKeyCountArgs,
            GetPreKeyCountRequest,
            GetPreKeyCountResponse,
            GetPreKeyCountOut,
        >,
    > {
        let method = "/org.signal.chat.keys.Keys/GetPreKeyCount";
        vec![
            GrpcTestCase {
                name: "zero counts".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GetPreKeyCountRequest {},
                response_grpc: GetPreKeyCountResponse::default(),
                response: PreKeyCounts {
                    aci_ec_pre_key_count: 0,
                    aci_kem_pre_key_count: 0,
                    pni_ec_pre_key_count: 0,
                    pni_kem_pre_key_count: 0,
                },
            },
            // Distinct values for each field, to catch any transposition of
            // the four same-typed counts.
            GrpcTestCase {
                name: "distinct counts".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GetPreKeyCountRequest {},
                response_grpc: GetPreKeyCountResponse {
                    aci_ec_pre_key_count: 42,
                    aci_kem_pre_key_count: 17,
                    pni_ec_pre_key_count: 33,
                    pni_kem_pre_key_count: 8,
                },
                response: PreKeyCounts {
                    aci_ec_pre_key_count: 42,
                    aci_kem_pre_key_count: 17,
                    pni_ec_pre_key_count: 33,
                    pni_kem_pre_key_count: 8,
                },
            },
        ]
    }

    pub struct SetOneTimeEcPreKeysArgs {
        pub identity: ServiceIdKind,
        pub pre_keys: Vec<(PreKeyId, PublicKey)>,
    }

    pub fn set_one_time_ec_pre_keys_test_cases()
    -> Vec<GrpcTestCase<SetOneTimeEcPreKeysArgs, SetOneTimeEcPreKeysRequest, SetPreKeyResponse, ()>>
    {
        fn test_pre_key(key_id: u32, key_byte: u8) -> (PreKeyId, PublicKey) {
            (
                key_id.into(),
                PublicKey::from_djb_public_key_bytes(&[key_byte; 32]).expect("valid key bytes"),
            )
        }

        fn test_pre_key_proto(key_id: i32, key_byte: u8) -> EcPreKeyProto {
            // 0x05 is the serialization format tag for Curve25519 public keys.
            let mut public_key = vec![0x05];
            public_key.extend_from_slice(&[key_byte; 32]);
            EcPreKeyProto { key_id, public_key }
        }

        let method = "/org.signal.chat.keys.Keys/SetOneTimeEcPreKeys";
        vec![
            GrpcTestCase {
                name: "one ACI key".to_string(),
                method: method.to_string(),
                request: SetOneTimeEcPreKeysArgs {
                    identity: ServiceIdKind::Aci,
                    pre_keys: vec![test_pre_key(42, 0x10)],
                },
                request_grpc: SetOneTimeEcPreKeysRequest {
                    identity_type: IdentityType::Aci.into(),
                    pre_keys: vec![test_pre_key_proto(42, 0x10)],
                },
                response_grpc: SetPreKeyResponse {},
                response: (),
            },
            GrpcTestCase {
                name: "several PNI keys".to_string(),
                method: method.to_string(),
                request: SetOneTimeEcPreKeysArgs {
                    identity: ServiceIdKind::Pni,
                    pre_keys: vec![
                        test_pre_key(100, 0x20),
                        test_pre_key(101, 0x21),
                        test_pre_key(102, 0x22),
                    ],
                },
                request_grpc: SetOneTimeEcPreKeysRequest {
                    identity_type: IdentityType::Pni.into(),
                    pre_keys: vec![
                        test_pre_key_proto(100, 0x20),
                        test_pre_key_proto(101, 0x21),
                        test_pre_key_proto(102, 0x22),
                    ],
                },
                response_grpc: SetPreKeyResponse {},
                response: (),
            },
        ]
    }

    pub struct SetOneTimeKemPreKeysArgs {
        pub identity: ServiceIdKind,
        pub pre_keys: Vec<(KyberPreKeyId, kem::PublicKey, Box<[u8]>)>,
    }

    pub fn set_one_time_kem_pre_keys_test_cases() -> Vec<
        GrpcTestCase<
            SetOneTimeKemPreKeysArgs,
            SetOneTimeKemSignedPreKeysRequest,
            SetPreKeyResponse,
            (),
        >,
    > {
        fn test_pre_key(
            key_id: u32,
            key_byte: u8,
            signature_byte: u8,
        ) -> (KyberPreKeyId, kem::PublicKey, Box<[u8]>) {
            // 0x08 is the serialization format tag for Kyber1024 keys.
            let mut kem_bytes = vec![0x08];
            kem_bytes.extend(std::iter::repeat_n(key_byte, 1568));
            (
                key_id.into(),
                kem::PublicKey::deserialize(&kem_bytes).expect("valid key bytes"),
                Box::new([signature_byte; 64]),
            )
        }

        fn test_pre_key_proto(key_id: i32, key_byte: u8, signature_byte: u8) -> KemPreKeyProto {
            let mut kem_bytes = vec![0x08];
            kem_bytes.extend(std::iter::repeat_n(key_byte, 1568));
            KemPreKeyProto {
                key_id,
                public_key: kem_bytes,
                signature: vec![signature_byte; 64],
            }
        }

        let method = "/org.signal.chat.keys.Keys/SetOneTimeKemSignedPreKeys";
        vec![
            GrpcTestCase {
                name: "one ACI key".to_string(),
                method: method.to_string(),
                request: SetOneTimeKemPreKeysArgs {
                    identity: ServiceIdKind::Aci,
                    pre_keys: vec![test_pre_key(42, 0x10, 0x55)],
                },
                request_grpc: SetOneTimeKemSignedPreKeysRequest {
                    identity_type: IdentityType::Aci.into(),
                    pre_keys: vec![test_pre_key_proto(42, 0x10, 0x55)],
                },
                response_grpc: SetPreKeyResponse {},
                response: (),
            },
            GrpcTestCase {
                name: "several PNI keys".to_string(),
                method: method.to_string(),
                request: SetOneTimeKemPreKeysArgs {
                    identity: ServiceIdKind::Pni,
                    pre_keys: vec![
                        test_pre_key(100, 0x20, 0x50),
                        test_pre_key(101, 0x21, 0x51),
                        test_pre_key(102, 0x22, 0x52),
                    ],
                },
                request_grpc: SetOneTimeKemSignedPreKeysRequest {
                    identity_type: IdentityType::Pni.into(),
                    pre_keys: vec![
                        test_pre_key_proto(100, 0x20, 0x50),
                        test_pre_key_proto(101, 0x21, 0x51),
                        test_pre_key_proto(102, 0x22, 0x52),
                    ],
                },
                response_grpc: SetPreKeyResponse {},
                response: (),
            },
        ]
    }

    pub struct SetSignedEcPreKeyArgs {
        pub identity: ServiceIdKind,
        pub pre_key: (SignedPreKeyId, PublicKey, Box<[u8]>),
    }

    pub fn set_signed_ec_pre_key_test_cases()
    -> Vec<GrpcTestCase<SetSignedEcPreKeyArgs, SetEcSignedPreKeyRequest, SetPreKeyResponse, ()>>
    {
        fn test_pre_key(
            key_id: u32,
            key_byte: u8,
            signature_byte: u8,
        ) -> (SignedPreKeyId, PublicKey, Box<[u8]>) {
            (
                key_id.into(),
                PublicKey::from_djb_public_key_bytes(&[key_byte; 32]).expect("valid key bytes"),
                Box::new([signature_byte; 64]),
            )
        }

        fn test_pre_key_proto(
            key_id: i32,
            key_byte: u8,
            signature_byte: u8,
        ) -> EcSignedPreKeyProto {
            // 0x05 is the serialization format tag for Curve25519 public keys.
            let mut public_key = vec![0x05];
            public_key.extend_from_slice(&[key_byte; 32]);
            EcSignedPreKeyProto {
                key_id,
                public_key,
                signature: vec![signature_byte; 64],
            }
        }

        let method = "/org.signal.chat.keys.Keys/SetEcSignedPreKey";
        vec![GrpcTestCase {
            name: "PNI".to_string(),
            method: method.to_string(),
            request: SetSignedEcPreKeyArgs {
                identity: ServiceIdKind::Pni,
                pre_key: test_pre_key(42, 0x10, 0x55),
            },
            request_grpc: SetEcSignedPreKeyRequest {
                identity_type: IdentityType::Pni.into(),
                signed_pre_key: Some(test_pre_key_proto(42, 0x10, 0x55)),
            },
            response_grpc: SetPreKeyResponse {},
            response: (),
        }]
    }

    pub struct SetLastResortKemPreKeyArgs {
        pub identity: ServiceIdKind,
        pub pre_key: (KyberPreKeyId, kem::PublicKey, Box<[u8]>),
    }

    pub fn set_last_resort_kem_pre_key_test_cases() -> Vec<
        GrpcTestCase<
            SetLastResortKemPreKeyArgs,
            SetKemLastResortPreKeyRequest,
            SetPreKeyResponse,
            (),
        >,
    > {
        fn test_pre_key(
            key_id: u32,
            key_byte: u8,
            signature_byte: u8,
        ) -> (KyberPreKeyId, kem::PublicKey, Box<[u8]>) {
            // 0x08 is the serialization format tag for Kyber1024 keys.
            let mut kem_bytes = vec![0x08];
            kem_bytes.extend(std::iter::repeat_n(key_byte, 1568));
            (
                key_id.into(),
                kem::PublicKey::deserialize(&kem_bytes).expect("valid key bytes"),
                Box::new([signature_byte; 64]),
            )
        }

        fn test_pre_key_proto(key_id: i32, key_byte: u8, signature_byte: u8) -> KemPreKeyProto {
            let mut kem_bytes = vec![0x08];
            kem_bytes.extend(std::iter::repeat_n(key_byte, 1568));
            KemPreKeyProto {
                key_id,
                public_key: kem_bytes,
                signature: vec![signature_byte; 64],
            }
        }

        let method = "/org.signal.chat.keys.Keys/SetKemLastResortPreKey";
        vec![GrpcTestCase {
            name: "PNI".to_string(),
            method: method.to_string(),
            request: SetLastResortKemPreKeyArgs {
                identity: ServiceIdKind::Pni,
                pre_key: test_pre_key(42, 0x10, 0x55),
            },
            request_grpc: SetKemLastResortPreKeyRequest {
                identity_type: IdentityType::Pni.into(),
                signed_pre_key: Some(test_pre_key_proto(42, 0x10, 0x55)),
            },
            response_grpc: SetPreKeyResponse {},
            response: (),
        }]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::grpc::testutil::run_tests;

    #[test]
    fn test_get_pre_key_count() {
        use test_cases::*;
        run_tests(
            get_pre_key_count_test_cases(),
            |chat: Auth<_>, ()| async move { chat.get_pre_key_count().await },
            |resp, result| assert_eq!(resp, result.expect("success")),
        );
    }

    #[test]
    fn test_set_one_time_ec_pre_keys() {
        use test_cases::*;
        run_tests(
            set_one_time_ec_pre_keys_test_cases(),
            |chat: Auth<_>, SetOneTimeEcPreKeysArgs { identity, pre_keys }| async move {
                let pre_keys = pre_keys.iter().map(|(id, key)| PublicEcPreKey {
                    key_id: *id,
                    public_key: key,
                });
                chat.set_one_time_ec_pre_keys(identity, pre_keys).await
            },
            |(), result| result.expect("success"),
        );
    }

    #[test]
    fn test_set_one_time_kem_pre_keys() {
        use test_cases::*;
        run_tests(
            set_one_time_kem_pre_keys_test_cases(),
            |chat: Auth<_>, SetOneTimeKemPreKeysArgs { identity, pre_keys }| async move {
                let pre_keys = pre_keys.iter().map(|(id, key, sig)| PublicKemPreKey {
                    key_id: *id,
                    public_key: key,
                    signature: Cow::Borrowed(sig),
                });
                chat.set_one_time_kem_pre_keys(identity, pre_keys).await
            },
            |(), result| result.expect("success"),
        );
    }

    #[test]
    fn test_set_signed_ec_pre_key() {
        use test_cases::*;
        run_tests(
            set_signed_ec_pre_key_test_cases(),
            |chat: Auth<_>,
             SetSignedEcPreKeyArgs {
                 identity,
                 pre_key: (id, key, sig),
             }| async move {
                chat.set_signed_ec_pre_key(
                    identity,
                    PublicSignedEcPreKey {
                        key_id: id,
                        public_key: &key,
                        signature: Cow::Borrowed(&sig),
                    },
                )
                .await
            },
            |(), result| result.expect("success"),
        );
    }

    #[test]
    fn test_set_last_resort_kem_pre_key() {
        use test_cases::*;
        run_tests(
            set_last_resort_kem_pre_key_test_cases(),
            |chat: Auth<_>,
             SetLastResortKemPreKeyArgs {
                 identity,
                 pre_key: (id, key, sig),
             }| async move {
                chat.set_last_resort_kem_pre_key(
                    identity,
                    PublicKemPreKey {
                        key_id: id,
                        public_key: &key,
                        signature: Cow::Borrowed(&sig),
                    },
                )
                .await
            },
            |(), result| result.expect("success"),
        );
    }
}
