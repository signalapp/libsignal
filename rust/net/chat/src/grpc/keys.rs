//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::convert::Infallible;

use displaydoc::Display;
use itertools::Itertools as _;
use libsignal_core::{DeviceId, ServiceId, ServiceIdKind};
use libsignal_net_grpc::proto::chat::common::{
    EcPreKey as EcPreKeyProto, EcSignedPreKey as EcSignedPreKeyProto, IdentityType,
    KemSignedPreKey as KemPreKeyProto,
};
use libsignal_net_grpc::proto::chat::errors;
use libsignal_net_grpc::proto::chat::keys::keys_anonymous_client::KeysAnonymousClient;
use libsignal_net_grpc::proto::chat::keys::keys_client::KeysClient;
use libsignal_net_grpc::proto::chat::keys::{
    AccountPreKeyBundles, DevicePreKeyBundle, GetPreKeyCountRequest, GetPreKeyCountResponse,
    GetPreKeysAnonymousRequest, GetPreKeysAnonymousResponse, GetPreKeysRequest,
    SetEcSignedPreKeyRequest, SetKemLastResortPreKeyRequest, SetOneTimeEcPreKeysRequest,
    SetOneTimeKemSignedPreKeysRequest, SetPreKeyResponse, get_pre_keys_anonymous_request,
    get_pre_keys_anonymous_response,
};
use libsignal_protocol::{
    IdentityKey, KyberPreKeyId, PreKeyBundle, PreKeyId, PublicKey, SignedPreKeyId, kem,
};

use crate::api::{Auth, RequestError, Unauth, UserBasedAuthorization};
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

/// Specifier to limit scope of pre-keys request to a specific device or all devices on the account.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceSpecifier {
    /// Request pre-keys for all devices on the account.
    AllDevices,
    /// Request pre-keys for a specific device.
    Specific(DeviceId),
}

/// Recoverable errors produced by [`Unauth::get_pre_keys`].
#[derive(Debug, Display)]
pub enum GetPreKeysFailure {
    /// The provided authorization is invalid for this fetch.
    Unauthorized,
    /// No keys were found for the target account or device.
    NotFound,
}

impl From<UserBasedAuthorization> for get_pre_keys_anonymous_request::Authorization {
    fn from(value: UserBasedAuthorization) -> Self {
        match value {
            UserBasedAuthorization::AccessKey(uak) => Self::UnidentifiedAccessKey(uak.to_vec()),
            UserBasedAuthorization::Group(token) => {
                Self::GroupSendToken(zkgroup::serialize(&token))
            }
            UserBasedAuthorization::UnrestrictedUnauthenticatedAccess => {
                Self::UnrestrictedAccess(())
            }
        }
    }
}

impl std::fmt::Display for Redact<GetPreKeysAnonymousRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GetPreKeysAnonymousRequest {
            request,
            authorization,
        }) = self;
        let mut s = f.debug_struct("GetPreKeysAnonymousRequest");
        match request {
            Some(GetPreKeysRequest {
                target_identifier,
                device_id,
            }) => {
                s.field("target", &target_identifier.as_ref().map(Redact));
                s.field("device_id", device_id);
            }
            None => {
                s.field("request", &None::<()>);
            }
        }
        // Only the *kind* of authorization; never the credential itself.
        s.field(
            "authorization",
            &authorization.as_ref().map(|authorization| {
                use get_pre_keys_anonymous_request::Authorization;
                match authorization {
                    Authorization::UnidentifiedAccessKey(_) => "UnidentifiedAccessKey",
                    Authorization::GroupSendToken(_) => "GroupSendToken",
                    Authorization::UnrestrictedAccess(_) => "UnrestrictedAccess",
                }
            }),
        );
        s.finish()
    }
}

impl<T: GrpcServiceProvider> Unauth<T> {
    /// Fetch the identity key and pre-key bundles for `target`.
    pub async fn get_pre_keys(
        &self,
        auth: UserBasedAuthorization,
        target: ServiceId,
        device: DeviceSpecifier,
    ) -> Result<(IdentityKey, Vec<PreKeyBundle>), RequestError<GetPreKeysFailure>> {
        let mut client = KeysAnonymousClient::new(self.0.service());
        let request = GetPreKeysAnonymousRequest {
            request: Some(GetPreKeysRequest {
                target_identifier: Some(target.into()),
                device_id: match device {
                    DeviceSpecifier::AllDevices => None,
                    DeviceSpecifier::Specific(id) => Some(id.into()),
                },
            }),
            authorization: Some(auth.into()),
        };
        let desc = Redact(&request).to_string();
        let GetPreKeysAnonymousResponse { response } =
            log_and_send(Self::LOG_TAG, &desc, || client.get_pre_keys(request))
                .await?
                .into_inner();

        match response.ok_or_else(|| unexpected("missing response"))? {
            get_pre_keys_anonymous_response::Response::PreKeys(bundles) => {
                parse_account_pre_key_bundles(bundles)
            }
            get_pre_keys_anonymous_response::Response::TargetNotFound(errors::NotFound {}) => {
                Err(RequestError::Other(GetPreKeysFailure::NotFound))
            }
            get_pre_keys_anonymous_response::Response::FailedUnidentifiedAuthorization(
                errors::FailedUnidentifiedAuthorization { description },
            ) => {
                // Server says the description is log-safe.
                log::warn!("failed auth: {description}");
                Err(RequestError::Other(GetPreKeysFailure::Unauthorized))
            }
        }
    }
}

fn unexpected<E>(log_safe: &'static str) -> RequestError<E> {
    RequestError::Unexpected {
        log_safe: log_safe.to_owned(),
    }
}

fn parse_account_pre_key_bundles(
    bundles: AccountPreKeyBundles,
) -> Result<(IdentityKey, Vec<PreKeyBundle>), RequestError<GetPreKeysFailure>> {
    let AccountPreKeyBundles {
        identity_key,
        device_pre_keys,
        // Not yet exposed to callers.
        unrestricted_unidentified_access: _,
        unidentified_access_key_fingerprint: _,
    } = bundles;

    let identity_key = IdentityKey::try_from(identity_key.as_slice())
        .map_err(|_| unexpected("invalid identityKey"))?;

    let mut bundles = device_pre_keys
        .into_iter()
        .map(|(device_id, bundle)| build_bundle(&identity_key, device_id, bundle))
        .collect::<Result<Vec<_>, _>>()?;
    // HashMap iteration order isn't deterministic; sort so callers (and tests) get a
    // consistent ordering.
    bundles.sort_unstable_by_key(|bundle| bundle.device_id().expect("infallible getter"));

    Ok((identity_key, bundles))
}

fn build_bundle(
    identity_key: &IdentityKey,
    device_id: u32,
    bundle: DevicePreKeyBundle,
) -> Result<PreKeyBundle, RequestError<GetPreKeysFailure>> {
    let DevicePreKeyBundle {
        ec_signed_pre_key,
        ec_one_time_pre_key,
        kem_pre_key,
        registration_id,
    } = bundle;

    let device_id = DeviceId::try_from(device_id).map_err(|_| unexpected("invalid deviceId"))?;

    let EcSignedPreKeyProto {
        key_id: signed_pre_key_id,
        public_key: signed_pre_key_public,
        signature: signed_pre_key_signature,
    } = ec_signed_pre_key.ok_or_else(|| unexpected("missing ecSignedPreKey"))?;
    // Only check that a signature is present. It gets verified against the identity key by
    // libsignal-protocol when the bundle is used to start a session, not here.
    if signed_pre_key_signature.is_empty() {
        return Err(unexpected("empty ecSignedPreKey signature"));
    }
    let signed_pre_key_id = SignedPreKeyId::from(key_id_to_u32(signed_pre_key_id)?);
    let signed_pre_key_public = PublicKey::try_from(signed_pre_key_public.as_slice())
        .map_err(|_| unexpected("invalid ecSignedPreKey public key"))?;

    let pre_key = ec_one_time_pre_key
        .map(
            |EcPreKeyProto { key_id, public_key }| -> Result<_, RequestError<GetPreKeysFailure>> {
                Ok((
                    PreKeyId::from(key_id_to_u32(key_id)?),
                    PublicKey::try_from(public_key.as_slice())
                        .map_err(|_| unexpected("invalid ecOneTimePreKey public key"))?,
                ))
            },
        )
        .transpose()?;

    let KemPreKeyProto {
        key_id: kyber_pre_key_id,
        public_key: kyber_pre_key_public,
        signature: kyber_pre_key_signature,
    } = kem_pre_key.ok_or_else(|| unexpected("missing kemPreKey"))?;
    // As above, the signature is verified when starting a session.
    if kyber_pre_key_signature.is_empty() {
        return Err(unexpected("empty kemPreKey signature"));
    }
    let kyber_pre_key_id = key_id_to_u32(kyber_pre_key_id)?;
    let kyber_pre_key_public = kem::PublicKey::deserialize(kyber_pre_key_public.as_slice())
        .map_err(|_| unexpected("invalid kemPreKey public key"))?;

    PreKeyBundle::new(
        registration_id,
        device_id,
        pre_key,
        signed_pre_key_id,
        signed_pre_key_public,
        signed_pre_key_signature,
        kyber_pre_key_id.into(),
        kyber_pre_key_public,
        kyber_pre_key_signature,
        *identity_key,
    )
    .map_err(|_| unexpected("invalid pre-key bundle content"))
}

/// The proto uses `int32` for key IDs but the rest of libsignal uses `u32`; like the current
/// clients, treat an out-of-range ID as a malformed response.
fn key_id_to_u32(key_id: i32) -> Result<u32, RequestError<GetPreKeysFailure>> {
    u32::try_from(key_id).map_err(|_| unexpected("invalid key ID"))
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

    pub struct GetPreKeysArgs {
        pub auth: UserBasedAuthorization,
        pub target: ServiceId,
        pub device: DeviceSpecifier,
    }

    /// The interesting parts of a [`PreKeyBundle`], in a directly comparable form.
    pub struct ExpectedPreKeyBundle {
        pub device_id: DeviceId,
        pub registration_id: u32,
        pub pre_key: Option<(PreKeyId, PublicKey)>,
        pub signed_pre_key: (SignedPreKeyId, PublicKey, Vec<u8>),
        pub kyber_pre_key: (KyberPreKeyId, kem::PublicKey, Vec<u8>),
    }

    pub enum GetPreKeysOut {
        Success {
            identity_key: IdentityKey,
            bundles: Vec<ExpectedPreKeyBundle>,
        },
        NotFound,
        Unauthorized,
        Unexpected,
    }

    pub const TEST_ACI: uuid::Uuid = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
    pub const TEST_ACCESS_KEY: [u8; 16] = [0x11; 16];
    // From `SERIALIZED_GROUP_SEND_TOKEN` in `crate::api::testutil`.
    pub const TEST_GROUP_SEND_TOKEN: [u8; 33] = [
        0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 229,
        207, 139, 1, 0, 0,
    ];

    fn group_send_token() -> zkgroup::groups::GroupSendFullToken {
        zkgroup::deserialize(&TEST_GROUP_SEND_TOKEN).expect("structurally valid group-send token")
    }

    pub fn test_identity_key(fill: u8) -> IdentityKey {
        IdentityKey::try_from(test_ec_public_key_bytes(fill).as_slice())
            .expect("valid identity key")
    }

    pub fn test_ec_public_key(fill: u8) -> PublicKey {
        PublicKey::try_from(test_ec_public_key_bytes(fill).as_slice()).expect("valid EC public key")
    }

    pub fn test_kem_public_key(fill: u8) -> kem::PublicKey {
        kem::PublicKey::deserialize(test_kem_public_key_bytes(fill).as_slice())
            .expect("valid kyber public key")
    }

    pub fn test_ec_public_key_bytes(fill: u8) -> Vec<u8> {
        // 0x05 is the serialization format tag for Curve25519 public keys.
        let mut bytes = vec![0x05];
        bytes.extend(std::iter::repeat_n(fill, 32));
        bytes
    }

    pub fn test_kem_public_key_bytes(fill: u8) -> Vec<u8> {
        // 0x08 is the serialization format tag for Kyber1024 keys.
        let mut bytes = vec![0x08];
        // 1568 is kyber1024::Parameters::PUBLIC_KEY_LENGTH
        bytes.extend(std::iter::repeat_n(fill, 1568));
        bytes
    }

    fn target() -> ServiceId {
        libsignal_core::Aci::from(TEST_ACI).into()
    }

    fn grpc_device_bundle(
        registration_id: u32,
        signed_pre_key_id: i32,
        signed_fill: u8,
        pre_key: Option<(i32, u8)>,
        kyber_pre_key_id: i32,
        kyber_fill: u8,
    ) -> DevicePreKeyBundle {
        DevicePreKeyBundle {
            ec_signed_pre_key: Some(EcSignedPreKeyProto {
                key_id: signed_pre_key_id,
                public_key: test_ec_public_key_bytes(signed_fill),
                signature: vec![signed_fill; 64],
            }),
            ec_one_time_pre_key: pre_key.map(|(key_id, fill)| EcPreKeyProto {
                key_id,
                public_key: test_ec_public_key_bytes(fill),
            }),
            kem_pre_key: Some(KemPreKeyProto {
                key_id: kyber_pre_key_id,
                public_key: test_kem_public_key_bytes(kyber_fill),
                signature: vec![kyber_fill; 64],
            }),
            registration_id,
        }
    }

    fn expected_bundle(
        device_id: u32,
        registration_id: u32,
        signed_pre_key_id: u32,
        signed_fill: u8,
        pre_key: Option<(u32, u8)>,
        kyber_pre_key_id: u32,
        kyber_fill: u8,
    ) -> ExpectedPreKeyBundle {
        ExpectedPreKeyBundle {
            device_id: DeviceId::try_from(device_id).expect("valid device id"),
            registration_id,
            pre_key: pre_key
                .map(|(key_id, fill)| (PreKeyId::from(key_id), test_ec_public_key(fill))),
            signed_pre_key: (
                SignedPreKeyId::from(signed_pre_key_id),
                test_ec_public_key(signed_fill),
                vec![signed_fill; 64],
            ),
            kyber_pre_key: (
                KyberPreKeyId::from(kyber_pre_key_id),
                test_kem_public_key(kyber_fill),
                vec![kyber_fill; 64],
            ),
        }
    }

    fn pre_keys_response(
        identity_key: Vec<u8>,
        device_pre_keys: impl IntoIterator<Item = (u32, DevicePreKeyBundle)>,
    ) -> GetPreKeysAnonymousResponse {
        GetPreKeysAnonymousResponse {
            response: Some(get_pre_keys_anonymous_response::Response::PreKeys(
                AccountPreKeyBundles {
                    identity_key,
                    device_pre_keys: device_pre_keys.into_iter().collect(),
                    unrestricted_unidentified_access: false,
                    unidentified_access_key_fingerprint: vec![],
                },
            )),
        }
    }

    pub fn get_pre_keys_test_cases() -> Vec<
        GrpcTestCase<
            GetPreKeysArgs,
            GetPreKeysAnonymousRequest,
            GetPreKeysAnonymousResponse,
            GetPreKeysOut,
        >,
    > {
        let method = "/org.signal.chat.keys.KeysAnonymous/GetPreKeys";
        let request_for_device = |device_id: Option<u32>,
                                  authorization: get_pre_keys_anonymous_request::Authorization|
         -> GetPreKeysAnonymousRequest {
            GetPreKeysAnonymousRequest {
                request: Some(GetPreKeysRequest {
                    target_identifier: Some(target().into()),
                    device_id,
                }),
                authorization: Some(authorization),
            }
        };
        let access_key_auth = || {
            get_pre_keys_anonymous_request::Authorization::UnidentifiedAccessKey(
                TEST_ACCESS_KEY.to_vec(),
            )
        };

        let case_for_request =
            |name: &str,
             request: GetPreKeysArgs,
             request_grpc: GetPreKeysAnonymousRequest,
             response_grpc: GetPreKeysAnonymousResponse,
             expected_ret: GetPreKeysOut| GrpcTestCase {
                name: name.to_string(),
                method: method.to_string(),
                request,
                request_grpc,
                response_grpc,
                response: expected_ret,
            };

        let case = |name: &str,
                    response_grpc: GetPreKeysAnonymousResponse,
                    expected_ret: GetPreKeysOut| {
            case_for_request(
                name,
                GetPreKeysArgs {
                    auth: UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                    target: target(),
                    device: DeviceSpecifier::AllDevices,
                },
                request_for_device(None, access_key_auth()),
                response_grpc,
                expected_ret,
            )
        };

        vec![
            case_for_request(
                "success with all keys for a specific device",
                GetPreKeysArgs {
                    auth: UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                    target: target(),
                    device: DeviceSpecifier::Specific(
                        DeviceId::try_from(2u32).expect("valid device id"),
                    ),
                },
                request_for_device(Some(2), access_key_auth()),
                pre_keys_response(
                    test_ec_public_key_bytes(0xAA),
                    [(
                        2,
                        grpc_device_bundle(1234, 7, 0xBB, Some((5, 0xDD)), 9, 0xEE),
                    )],
                ),
                GetPreKeysOut::Success {
                    identity_key: test_identity_key(0xAA),
                    bundles: vec![expected_bundle(2, 1234, 7, 0xBB, Some((5, 0xDD)), 9, 0xEE)],
                },
            ),
            case(
                "success for all devices",
                pre_keys_response(
                    test_ec_public_key_bytes(0xA1),
                    [
                        (
                            3,
                            grpc_device_bundle(5678, 13, 0x21, Some((11, 0x43)), 15, 0x54),
                        ),
                        (
                            2,
                            grpc_device_bundle(1234, 7, 0xB2, Some((5, 0xD4)), 9, 0xE5),
                        ),
                    ],
                ),
                GetPreKeysOut::Success {
                    identity_key: test_identity_key(0xA1),
                    // Sorted by device ID regardless of map ordering.
                    bundles: vec![
                        expected_bundle(2, 1234, 7, 0xB2, Some((5, 0xD4)), 9, 0xE5),
                        expected_bundle(3, 5678, 13, 0x21, Some((11, 0x43)), 15, 0x54),
                    ],
                },
            ),
            case_for_request(
                "success without one-time pre-key, unrestricted access",
                GetPreKeysArgs {
                    auth: UserBasedAuthorization::UnrestrictedUnauthenticatedAccess,
                    target: target(),
                    device: DeviceSpecifier::Specific(
                        DeviceId::try_from(2u32).expect("valid device id"),
                    ),
                },
                request_for_device(
                    Some(2),
                    get_pre_keys_anonymous_request::Authorization::UnrestrictedAccess(()),
                ),
                pre_keys_response(
                    test_ec_public_key_bytes(0x12),
                    [(2, grpc_device_bundle(1234, 7, 0x34, None, 9, 0x78))],
                ),
                GetPreKeysOut::Success {
                    identity_key: test_identity_key(0x12),
                    bundles: vec![expected_bundle(2, 1234, 7, 0x34, None, 9, 0x78)],
                },
            ),
            case_for_request(
                "group-send authorization",
                GetPreKeysArgs {
                    auth: UserBasedAuthorization::Group(group_send_token()),
                    target: target(),
                    device: DeviceSpecifier::AllDevices,
                },
                request_for_device(
                    None,
                    get_pre_keys_anonymous_request::Authorization::GroupSendToken(
                        TEST_GROUP_SEND_TOKEN.to_vec(),
                    ),
                ),
                GetPreKeysAnonymousResponse {
                    response: Some(get_pre_keys_anonymous_response::Response::TargetNotFound(
                        errors::NotFound {},
                    )),
                },
                GetPreKeysOut::NotFound,
            ),
            case(
                "target not found",
                GetPreKeysAnonymousResponse {
                    response: Some(get_pre_keys_anonymous_response::Response::TargetNotFound(
                        errors::NotFound {},
                    )),
                },
                GetPreKeysOut::NotFound,
            ),
            case(
                "failed unidentified authorization",
                GetPreKeysAnonymousResponse {
                    response: Some(
                        get_pre_keys_anonymous_response::Response::FailedUnidentifiedAuthorization(
                            errors::FailedUnidentifiedAuthorization {
                                description: "bad access key".to_string(),
                            },
                        ),
                    ),
                },
                GetPreKeysOut::Unauthorized,
            ),
            case(
                "missing response",
                GetPreKeysAnonymousResponse { response: None },
                GetPreKeysOut::Unexpected,
            ),
            case(
                "invalid identity key",
                pre_keys_response(vec![0x00, 0x01, 0x02], []),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "invalid device ID",
                pre_keys_response(
                    test_ec_public_key_bytes(0x10),
                    [(
                        0,
                        grpc_device_bundle(1234, 7, 0x11, Some((5, 0x13)), 9, 0x14),
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "missing signed pre-key",
                pre_keys_response(
                    test_ec_public_key_bytes(0x20),
                    [(
                        2,
                        DevicePreKeyBundle {
                            ec_signed_pre_key: None,
                            ..grpc_device_bundle(1234, 7, 0x21, Some((5, 0x22)), 9, 0x23)
                        },
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "empty signed pre-key signature",
                pre_keys_response(
                    test_ec_public_key_bytes(0x28),
                    [(
                        2,
                        DevicePreKeyBundle {
                            ec_signed_pre_key: Some(EcSignedPreKeyProto {
                                key_id: 7,
                                public_key: test_ec_public_key_bytes(0x29),
                                signature: vec![],
                            }),
                            ..grpc_device_bundle(1234, 7, 0x29, Some((5, 0x2A)), 9, 0x2B)
                        },
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "missing pq pre-key",
                pre_keys_response(
                    test_ec_public_key_bytes(0x30),
                    [(
                        2,
                        DevicePreKeyBundle {
                            kem_pre_key: None,
                            ..grpc_device_bundle(1234, 7, 0x31, Some((5, 0x33)), 9, 0x34)
                        },
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "empty pq pre-key signature",
                pre_keys_response(
                    test_ec_public_key_bytes(0x38),
                    [(
                        2,
                        DevicePreKeyBundle {
                            kem_pre_key: Some(KemPreKeyProto {
                                key_id: 9,
                                public_key: test_kem_public_key_bytes(0x3B),
                                signature: vec![],
                            }),
                            ..grpc_device_bundle(1234, 7, 0x39, Some((5, 0x3A)), 9, 0x3B)
                        },
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "negative key ID",
                pre_keys_response(
                    test_ec_public_key_bytes(0x40),
                    [(
                        2,
                        grpc_device_bundle(1234, -7, 0x41, Some((5, 0x42)), 9, 0x43),
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "invalid signed pre-key public key",
                pre_keys_response(
                    test_ec_public_key_bytes(0x50),
                    [(
                        2,
                        DevicePreKeyBundle {
                            ec_signed_pre_key: Some(EcSignedPreKeyProto {
                                key_id: 7,
                                public_key: vec![0x00],
                                signature: vec![0x51; 64],
                            }),
                            ..grpc_device_bundle(1234, 7, 0x51, Some((5, 0x52)), 9, 0x53)
                        },
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "invalid one-time pre-key public key",
                pre_keys_response(
                    test_ec_public_key_bytes(0x60),
                    [(
                        2,
                        DevicePreKeyBundle {
                            ec_one_time_pre_key: Some(EcPreKeyProto {
                                key_id: 5,
                                public_key: vec![0x00],
                            }),
                            ..grpc_device_bundle(1234, 7, 0x61, None, 9, 0x63)
                        },
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
            case(
                "invalid kem pre-key public key",
                pre_keys_response(
                    test_ec_public_key_bytes(0x70),
                    [(
                        2,
                        DevicePreKeyBundle {
                            kem_pre_key: Some(KemPreKeyProto {
                                key_id: 9,
                                // A KEM type byte with no key material following it.
                                public_key: vec![0x08],
                                signature: vec![0x73; 64],
                            }),
                            ..grpc_device_bundle(1234, 7, 0x71, Some((5, 0x72)), 9, 0x73)
                        },
                    )],
                ),
                GetPreKeysOut::Unexpected,
            ),
        ]
    }
}

#[cfg(test)]
mod test {
    use futures_util::FutureExt as _;

    use super::*;
    use crate::api::DisconnectedError;
    use crate::grpc::testutil::{RequestValidator, err, req, run_tests};

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

    fn check_expected_bundles(
        expected: &[test_cases::ExpectedPreKeyBundle],
        actual: &[PreKeyBundle],
    ) {
        assert_eq!(expected.len(), actual.len());
        for (expected, actual) in expected.iter().zip(actual) {
            // Destructure so that a newly added field can't be forgotten here.
            let test_cases::ExpectedPreKeyBundle {
                device_id,
                registration_id,
                pre_key,
                signed_pre_key: (signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature),
                kyber_pre_key: (kyber_pre_key_id, kyber_pre_key_public, kyber_pre_key_signature),
            } = expected;
            assert_eq!(*device_id, actual.device_id().expect("device id"));
            assert_eq!(
                *registration_id,
                actual.registration_id().expect("registration id")
            );
            assert_eq!(
                pre_key.as_ref().map(|(id, _)| *id),
                actual.pre_key_id().expect("pre-key id")
            );
            assert_eq!(
                pre_key.as_ref().map(|(_, key)| *key),
                actual.pre_key_public().expect("pre-key public")
            );
            assert_eq!(
                *signed_pre_key_id,
                actual.signed_pre_key_id().expect("signed pre-key id")
            );
            assert_eq!(
                *signed_pre_key_public,
                actual.signed_pre_key_public().expect("signed pre-key")
            );
            assert_eq!(
                signed_pre_key_signature.as_slice(),
                actual
                    .signed_pre_key_signature()
                    .expect("signed pre-key signature")
            );
            assert_eq!(
                *kyber_pre_key_id,
                actual.kyber_pre_key_id().expect("kyber pre-key id")
            );
            assert_eq!(
                kyber_pre_key_public,
                actual.kyber_pre_key_public().expect("kyber pre-key")
            );
            assert_eq!(
                kyber_pre_key_signature.as_slice(),
                actual
                    .kyber_pre_key_signature()
                    .expect("kyber pre-key signature")
            );
        }
    }

    #[test]
    fn test_get_pre_keys() {
        use test_cases::*;
        run_tests(
            get_pre_keys_test_cases(),
            |chat: Unauth<_>,
             GetPreKeysArgs {
                 auth,
                 target,
                 device,
             }| async move { chat.get_pre_keys(auth, target, device).await },
            |resp, result| match resp {
                GetPreKeysOut::Success {
                    identity_key,
                    bundles,
                } => {
                    let (actual_identity_key, actual_bundles) = result.expect("success");
                    assert_eq!(identity_key, actual_identity_key);
                    check_expected_bundles(&bundles, &actual_bundles);
                }
                GetPreKeysOut::NotFound => {
                    // PreKeyBundle doesn't implement Debug, so no assert_matches! here.
                    assert!(matches!(
                        result,
                        Err(RequestError::Other(GetPreKeysFailure::NotFound))
                    ))
                }
                GetPreKeysOut::Unauthorized => {
                    assert!(matches!(
                        result,
                        Err(RequestError::Other(GetPreKeysFailure::Unauthorized))
                    ))
                }
                GetPreKeysOut::Unexpected => {
                    assert!(matches!(result, Err(RequestError::Unexpected { .. })))
                }
            },
        );
    }

    #[test]
    fn test_get_pre_keys_grpc_error() {
        use test_cases::*;
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.keys.KeysAnonymous/GetPreKeys",
                GetPreKeysAnonymousRequest {
                    request: Some(GetPreKeysRequest {
                        target_identifier: Some(
                            ServiceId::from(libsignal_core::Aci::from(TEST_ACI)).into(),
                        ),
                        device_id: None,
                    }),
                    authorization: Some(
                        get_pre_keys_anonymous_request::Authorization::UnidentifiedAccessKey(
                            TEST_ACCESS_KEY.to_vec(),
                        ),
                    ),
                },
            ),
            response: err(tonic::Code::Internal),
        };

        let result = Unauth(&validator)
            .get_pre_keys(
                UserBasedAuthorization::AccessKey(TEST_ACCESS_KEY),
                libsignal_core::Aci::from(TEST_ACI).into(),
                DeviceSpecifier::AllDevices,
            )
            .now_or_never()
            .expect("sync");
        // Unexpected gRPC-level errors are treated as transport errors.
        assert!(matches!(
            result,
            Err(RequestError::Disconnected(
                DisconnectedError::Transport { .. }
            ))
        ));
    }
}
