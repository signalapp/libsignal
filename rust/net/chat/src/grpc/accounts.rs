//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_account_keys::{EncryptedMfaMetadata, InvalidMfaMetadata, MfaMetadata, SvrKey};
use libsignal_core::LogSafeDisplay;
use libsignal_net_grpc::proto::chat::account::accounts_client::AccountsClient;
use libsignal_net_grpc::proto::chat::account::list_mfa_keys_response::mfa_key_metadata::MfaKeyType as GrpcMfaKeyType;
use libsignal_net_grpc::proto::chat::account::{
    ClearRegistrationLockRequest, ClearRegistrationLockResponse, ConfirmTotpKeyRequest,
    ConfirmTotpKeyResponse, DeleteAccountRequest, DeleteAccountResponse, GenerateTotpKeyRequest,
    GenerateTotpKeyResponse, ListMfaKeysRequest, ListMfaKeysResponse, RemoveMfaKeyRequest,
    RemoveMfaKeyResponse, SetDiscoverableByPhoneNumberRequest,
    SetDiscoverableByPhoneNumberResponse, SetMfaKeyMetadataRequest, SetMfaKeyMetadataResponse,
    SetRegistrationLockRequest, SetRegistrationLockResponse,
    SetRegistrationRecoveryPasswordRequest, SetRegistrationRecoveryPasswordResponse,
    TotpParameters as GrpcTotpParameters, confirm_totp_key_response, generate_totp_key_response,
    list_mfa_keys_response, set_mfa_key_metadata_response,
};
use libsignal_net_grpc::proto::chat::errors;

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, GrpcTestCase, log_and_send};
use crate::logging::Redact;

impl std::fmt::Display for Redact<DeleteAccountRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(DeleteAccountRequest {}) = self;
        f.debug_struct("DeleteAccountRequest").finish()
    }
}

/// The largest identifier the server will assign to an MFA key.
/// See rust/net/grpc/proto/org/signal/chat/account.proto
pub const MAX_MFA_KEY_ID: u32 = 127;

/// The account-specific identifier of a confirmed MFA key, in `0..=`[`MAX_MFA_KEY_ID`].
///
/// Identifiers are assigned by the server, and are handed out by [`Auth::confirm_totp_key`] and
/// [`Auth::list_mfa_keys`]. They are only meaningful for the account that produced them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MfaKeyId(u32);

#[derive(displaydoc::Display, Debug)]
/// MFA key ID {0} is out of range
pub struct MfaKeyIdOutOfRange(pub u32);

impl TryFrom<u32> for MfaKeyId {
    type Error = MfaKeyIdOutOfRange;

    fn try_from(id: u32) -> Result<Self, Self::Error> {
        if id > MAX_MFA_KEY_ID {
            return Err(MfaKeyIdOutOfRange(id));
        }
        Ok(Self(id))
    }
}

impl From<MfaKeyId> for u32 {
    fn from(MfaKeyId(id): MfaKeyId) -> Self {
        id
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct TotpParameters {
    /// The HMAC algorithm (e.g. "HmacSHA256") used by the TOTP generator.
    pub algorithm: String,
    /// The length of one-time passwords (in decimal digits) produced and expected by the TOTP
    /// generator.
    pub password_length: u32,
    /// The time step (in seconds) used by the TOTP generator.
    pub time_step_seconds: u32,
}

/// A newly-generated TOTP key that is not yet active.
///
/// Returned by [`Auth::generate_totp_key`]; the key only starts being accepted for the account
/// once it is confirmed via [`Auth::confirm_totp_key`].
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct PendingTotpKey {
    /// The raw TOTP key.
    pub key: Vec<u8>,
    /// The TOTP parameters associated with the generated key.
    pub parameters: TotpParameters,
}

/// A confirmed multi-factor authentication (MFA) key on the account, as returned by
/// [`Auth::list_mfa_keys`].
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct ConfirmedMfaKey {
    /// The account-specific identifier for this key.
    pub id: MfaKeyId,
    /// The user-specified name and creation time attached to this key.
    pub metadata: Result<MfaMetadata, InvalidMfaMetadata>,
    /// What kind of MFA key this is.
    pub kind: MfaKeyKind,
}

/// The kind of an MFA key on the account.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MfaKeyKind {
    /// A TOTP key; see [`Auth::generate_totp_key`].
    Totp,
    /// A kind of key this version of libsignal doesn't know about.
    Unknown,
}

#[derive(displaydoc::Display, Debug)]
pub enum GenerateTotpKeyError {
    /// The account already has too many TOTP keys; one must be removed before adding more
    TooManyTotpKeys,
    /// The account already has too many MFA keys of all kinds; one must be removed first
    TooManyMfaKeys,
}
impl LogSafeDisplay for GenerateTotpKeyError {}

#[derive(displaydoc::Display, Debug)]
pub enum ConfirmTotpKeyError {
    /// The provided one-time password was not accepted for the pending TOTP key
    OneTimePasswordNotVerified,
    /// The account already has too many MFA keys of all kinds; one must be removed first
    TooManyMfaKeys,
}
impl LogSafeDisplay for ConfirmTotpKeyError {}

#[derive(displaydoc::Display, Debug)]
/// No confirmed MFA key with the provided identifier was found on the account
pub struct MfaKeyNotFound;
impl LogSafeDisplay for MfaKeyNotFound {}

fn parse_mfa_key_id<E>(key_id: u32) -> Result<MfaKeyId, RequestError<E>> {
    MfaKeyId::try_from(key_id).map_err(|e| RequestError::Unexpected {
        log_safe: e.to_string(),
    })
}

fn parse_totp_parameters<E>(
    parameters: GrpcTotpParameters,
) -> Result<TotpParameters, RequestError<E>> {
    let GrpcTotpParameters {
        algorithm,
        password_length,
        time_step_seconds,
    } = parameters;
    // TODO: The server should enforce this, but for now, we can enforce this.
    let is_libsignal_safe = |value: u32| value != 0 && i32::try_from(value).is_ok();
    if !is_libsignal_safe(password_length) || !is_libsignal_safe(time_step_seconds) {
        return Err(RequestError::Unexpected {
            log_safe: "unreasonable TOTP parameters".to_string(),
        });
    }
    Ok(TotpParameters {
        algorithm,
        password_length,
        time_step_seconds,
    })
}

impl std::fmt::Display for Redact<SetRegistrationLockRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetRegistrationLockRequest { registration_lock }) = self;
        f.debug_struct("SetRegistrationLockRequest")
            .field("registration_lock_len", &registration_lock.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<ClearRegistrationLockRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(ClearRegistrationLockRequest {}) = self;
        f.debug_struct("ClearRegistrationLockRequest").finish()
    }
}

impl std::fmt::Display for Redact<SetRegistrationRecoveryPasswordRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetRegistrationRecoveryPasswordRequest {
            registration_recovery_password,
        }) = self;
        f.debug_struct("SetRegistrationRecoveryPasswordRequest")
            .field(
                "registration_recovery_password_len",
                &registration_recovery_password.len(),
            )
            .finish()
    }
}

impl std::fmt::Display for Redact<SetDiscoverableByPhoneNumberRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetDiscoverableByPhoneNumberRequest {
            discoverable_by_phone_number,
        }) = self;
        f.debug_struct("SetDiscoverableByPhoneNumberRequest")
            .field("discoverable", discoverable_by_phone_number)
            .finish()
    }
}

impl std::fmt::Display for Redact<GenerateTotpKeyRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GenerateTotpKeyRequest {}) = self;
        f.debug_struct("GenerateTotpKeyRequest").finish()
    }
}

impl std::fmt::Display for Redact<ConfirmTotpKeyRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(ConfirmTotpKeyRequest {
            one_time_password: _,
            metadata_ciphertext,
        }) = self;
        f.debug_struct("ConfirmTotpKeyRequest")
            .field("metadata_ciphertext.len", &metadata_ciphertext.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<ListMfaKeysRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(ListMfaKeysRequest {}) = self;
        f.debug_struct("ListMfaKeysRequest").finish()
    }
}

impl std::fmt::Display for Redact<SetMfaKeyMetadataRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetMfaKeyMetadataRequest {
            key_id,
            metadata_ciphertext,
        }) = self;
        f.debug_struct("SetMfaKeyMetadataRequest")
            .field("key_id", key_id)
            .field("metadata_ciphertext.len", &metadata_ciphertext.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<RemoveMfaKeyRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(RemoveMfaKeyRequest { key_id }) = self;
        f.debug_struct("RemoveMfaKeyRequest")
            .field("key_id", key_id)
            .finish()
    }
}

impl<T: GrpcServiceProvider> Auth<T> {
    /// Deletes the authenticated account, purging all associated data in the
    /// process.
    ///
    /// Only the account's primary device may delete the account; the server
    /// rejects calls from linked devices as a programmer error, surfaced as
    /// [`RequestError::Unexpected`].
    ///
    /// Deleting the account also invalidates its connections, so the response
    /// can race the resulting disconnect. If the connection is interrupted
    /// before a response arrives, the deletion may nevertheless have taken
    /// effect; callers should not treat a transport error as proof the account
    /// still exists.
    pub async fn delete_account(&self) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = DeleteAccountRequest {};
        let desc = Redact(&request).to_string();
        let DeleteAccountResponse {} =
            log_and_send("auth", &desc, || client.delete_account(request))
                .await?
                .into_inner();
        Ok(())
    }

    /// Sets the registration lock for the authenticated account, given the account's SVR key.
    ///
    /// libsignal derives the registration lock token from the SVR key (see
    /// [`SvrKey::derive_registration_lock`]) and sends only that derived token; the SVR key itself
    /// never leaves the device.
    ///
    /// While the registration lock is set, re-registering the account's phone
    /// number requires proving knowledge of the token.
    ///
    /// Only the account's primary device may set a registration lock. Removing
    /// a registration lock is a separate operation; see
    /// [`Self::clear_registration_lock`].
    pub async fn set_registration_lock(
        &self,
        svr_key: SvrKey,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = SetRegistrationLockRequest {
            registration_lock: svr_key.derive_registration_lock().to_vec(),
        };
        let desc = Redact(&request).to_string();
        let SetRegistrationLockResponse {} =
            log_and_send("auth", &desc, || client.set_registration_lock(request))
                .await?
                .into_inner();
        Ok(())
    }

    /// Removes any registration lock from the authenticated account.
    ///
    /// This also succeeds if the account has no registration lock set, so a
    /// caller retrying a removal sees the same result as the original call.
    ///
    /// Only the account's primary device may clear a registration lock; the
    /// server rejects calls from linked devices as a programmer error,
    /// surfaced as [`RequestError::Unexpected`].
    pub async fn clear_registration_lock(&self) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = ClearRegistrationLockRequest {};
        let desc = Redact(&request).to_string();
        let ClearRegistrationLockResponse {} =
            log_and_send("auth", &desc, || client.clear_registration_lock(request))
                .await?
                .into_inner();
        Ok(())
    }

    /// Derives and sets the registration recovery password for the authenticated account from its
    /// SVR key.
    ///
    /// Only the derived registration recovery password is sent; the SVR key itself never leaves
    /// the device.
    pub async fn set_registration_recovery_password_from_svr_key(
        &self,
        svr_key: SvrKey,
    ) -> Result<(), RequestError<Infallible>> {
        self.set_registration_recovery_password(svr_key.derive_registration_recovery_password())
            .await
    }

    /// Sets an already-derived registration recovery password for the authenticated account.
    ///
    /// `registration_recovery_password` can be derived from the account's SVR key using
    /// [`SvrKey::derive_registration_recovery_password`].
    ///
    /// The registration recovery password lets the account re-register its phone number without
    /// SMS verification. The server stores it against the account's phone-number identity (PNI),
    /// and any of the account's devices may set it.
    pub async fn set_registration_recovery_password(
        &self,
        registration_recovery_password: [u8; 32],
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = SetRegistrationRecoveryPasswordRequest {
            registration_recovery_password: registration_recovery_password.to_vec(),
        };
        let desc = Redact(&request).to_string();
        let SetRegistrationRecoveryPasswordResponse {} = log_and_send("auth", &desc, || {
            client.set_registration_recovery_password(request)
        })
        .await?
        .into_inner();
        Ok(())
    }

    /// Sets whether the authenticated account may be discovered by phone number via the Contact
    /// Discovery Service (CDS).
    ///
    /// If `false`, other users must discover this account by other means (e.g. by username).
    pub async fn set_discoverable_by_phone_number(
        &self,
        discoverable: bool,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = SetDiscoverableByPhoneNumberRequest {
            discoverable_by_phone_number: discoverable,
        };
        let desc = Redact(&request).to_string();
        let SetDiscoverableByPhoneNumberResponse {} = log_and_send("auth", &desc, || {
            client.set_discoverable_by_phone_number(request)
        })
        .await?
        .into_inner();
        Ok(())
    }

    /// Generates and stores a new pending TOTP key for the authenticated account.
    ///
    /// The key is generated by the server and returned along with the parameters a TOTP generator
    /// needs to derive one-time passwords from it.
    ///
    /// The key does not become active until the client calls [`Self::confirm_totp_key`] to prove
    /// it can generate one-time passwords using the new key. The caller has 24 hours to confirm
    /// the key after it has been generated. This is the only time the key material for this TOTP
    /// key is available; if it is lost, a new one will need to be generated.
    ///
    /// Fails with a [`GenerateTotpKeyError`] if the account is already at either of the server's
    /// key limits.
    pub async fn generate_totp_key(
        &self,
    ) -> Result<PendingTotpKey, RequestError<GenerateTotpKeyError>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = GenerateTotpKeyRequest {};
        let desc = Redact(&request).to_string();
        let GenerateTotpKeyResponse { response } =
            log_and_send("auth", &desc, || client.generate_totp_key(request))
                .await?
                .into_inner();

        match response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_string(),
        })? {
            generate_totp_key_response::Response::KeyGenerated(
                generate_totp_key_response::KeyGenerated {
                    key,
                    totp_parameters,
                },
            ) => Ok(PendingTotpKey {
                key,
                parameters: parse_totp_parameters(totp_parameters.ok_or_else(|| {
                    RequestError::Unexpected {
                        log_safe: "missing TOTP parameters".to_string(),
                    }
                })?)?,
            }),
            generate_totp_key_response::Response::TooManyTotpKeys(errors::FailedPrecondition {
                description,
            }) => {
                log::warn!("too many TOTP keys: {description}");
                Err(RequestError::Other(GenerateTotpKeyError::TooManyTotpKeys))
            }
            generate_totp_key_response::Response::TooManyMfaKeys(errors::FailedPrecondition {
                description,
            }) => {
                log::warn!("too many MFA keys: {description}");
                Err(RequestError::Other(GenerateTotpKeyError::TooManyMfaKeys))
            }
        }
    }

    /// Confirms the account's pending TOTP key (see [`Self::generate_totp_key`]), thus activating
    /// it.
    ///
    /// A TOTP key must be confirmed within 24 hours of its generation.
    ///
    /// The `one_time_password` is a one-time password derived from the pending key. This should be
    /// provided by the user, proving they have stored the key and can correctly generate passwords
    /// from it going forward.
    ///
    /// The `metadata` is attached to the newly-confirmed key and stored on the server alongside
    /// the new key. It is stored encrypted, so that it may not be read by the server.
    ///
    /// Returns the account-specific identifier assigned to the newly-confirmed key. Fails with a
    /// [`ConfirmTotpKeyError`] if the one-time password is rejected, or if the account filled up
    /// with MFA keys between generating and confirming this one.
    pub async fn confirm_totp_key(
        &self,
        one_time_password: u32,
        metadata: &MfaMetadata,
        svr_key: &SvrKey,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<MfaKeyId, RequestError<ConfirmTotpKeyError>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = ConfirmTotpKeyRequest {
            one_time_password,
            metadata_ciphertext: metadata.encrypt(svr_key, rng).as_bytes().to_vec(),
        };
        let desc = Redact(&request).to_string();
        let ConfirmTotpKeyResponse { response } =
            log_and_send("auth", &desc, || client.confirm_totp_key(request))
                .await?
                .into_inner();

        match response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_string(),
        })? {
            confirm_totp_key_response::Response::KeyConfirmed(
                confirm_totp_key_response::KeyConfirmed { key_id },
            ) => parse_mfa_key_id(key_id),
            confirm_totp_key_response::Response::OneTimePasswordNotVerified(
                errors::FailedPrecondition { description },
            ) => {
                log::warn!("one-time password not verified: {description}");
                Err(RequestError::Other(
                    ConfirmTotpKeyError::OneTimePasswordNotVerified,
                ))
            }
            // The account filled up between generating and confirming this key.
            confirm_totp_key_response::Response::TooManyMfaKeys(errors::FailedPrecondition {
                description,
            }) => {
                log::warn!("too many MFA keys: {description}");
                Err(RequestError::Other(ConfirmTotpKeyError::TooManyMfaKeys))
            }
        }
    }

    /// Lists the confirmed MFA keys for the authenticated account.
    ///
    /// If the metadata for a given key cannot be decrypted using the provided [`SvrKey`] (e.g.
    /// because the SVR key / AEP has rotated since the key was stored), then
    /// [`ConfirmedMfaKey::metadata`] is set to the error for that element. The user can recover
    /// from this situation by setting the name, if they recall it, via
    /// [`Self::set_mfa_key_metadata`] with the matching key ID, or by purging the forgotten key
    /// via [`Self::remove_mfa_key`].
    ///
    /// Likewise, an entry of a kind this version of libsignal doesn't recognize is still listed,
    /// with [`MfaKeyKind::Unknown`] (e.g. because it was added from a linked device running a
    /// newer version of Signal).
    ///
    /// Pending (unconfirmed) keys are not included, and the key material itself is never
    /// returned; see [`ConfirmedMfaKey`].
    pub async fn list_mfa_keys(
        &self,
        svr_key: &SvrKey,
    ) -> Result<Vec<ConfirmedMfaKey>, RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = ListMfaKeysRequest {};
        let desc = Redact(&request).to_string();
        let ListMfaKeysResponse { keys } =
            log_and_send("auth", &desc, || client.list_mfa_keys(request))
                .await?
                .into_inner();

        let mut keys = keys
            .into_iter()
            .map(
                |(
                    id,
                    list_mfa_keys_response::MfaKeyMetadata {
                        metadata_ciphertext,
                        r#type,
                    },
                )|
                 -> Result<ConfirmedMfaKey, RequestError<Infallible>> {
                    // A kind of key this version doesn't know about fails to decode, and a server
                    // that didn't set the field at all decodes as `Unspecified`.
                    let kind = match GrpcMfaKeyType::try_from(r#type) {
                        Ok(GrpcMfaKeyType::Totp) => MfaKeyKind::Totp,
                        Ok(GrpcMfaKeyType::Unspecified) | Err(_) => MfaKeyKind::Unknown,
                    };
                    Ok(ConfirmedMfaKey {
                        id: parse_mfa_key_id(id)?,
                        metadata: EncryptedMfaMetadata::try_from(&metadata_ciphertext[..])
                            .and_then(|encrypted| encrypted.decrypt(svr_key)),
                        kind,
                    })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        keys.sort_by_key(|key| key.id);
        Ok(keys)
    }

    /// Replaces the metadata attached to the confirmed MFA key identified by `key_id`.
    pub async fn set_mfa_key_metadata(
        &self,
        key_id: MfaKeyId,
        metadata: &MfaMetadata,
        svr_key: &SvrKey,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<(), RequestError<MfaKeyNotFound>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = SetMfaKeyMetadataRequest {
            key_id: key_id.into(),
            metadata_ciphertext: metadata.encrypt(svr_key, rng).as_bytes().to_vec(),
        };
        let desc = Redact(&request).to_string();
        let SetMfaKeyMetadataResponse { response } =
            log_and_send("auth", &desc, || client.set_mfa_key_metadata(request))
                .await?
                .into_inner();

        match response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_string(),
        })? {
            set_mfa_key_metadata_response::Response::MetadataUpdated(
                set_mfa_key_metadata_response::MetadataUpdated {},
            ) => Ok(()),
            set_mfa_key_metadata_response::Response::KeyNotFound(errors::NotFound {}) => {
                Err(RequestError::Other(MfaKeyNotFound))
            }
        }
    }

    /// Removes the MFA key identified by `key_id` from the authenticated account.
    ///
    /// NB: This is idempotent; removing a key ID that is not on the account also succeeds.
    pub async fn remove_mfa_key(&self, key_id: MfaKeyId) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = RemoveMfaKeyRequest {
            key_id: key_id.into(),
        };
        let desc = Redact(&request).to_string();
        let RemoveMfaKeyResponse {} =
            log_and_send("auth", &desc, || client.remove_mfa_key(request))
                .await?
                .into_inner();
        Ok(())
    }
}

// Not cfg(test) so it can be accessed via bridging tests.
// These tests will get pruned via LTO tree shaking.
pub mod test_cases {
    use libsignal_account_keys::MFA_METADATA_CIPHERTEXT_LEN;
    use libsignal_protocol::Timestamp;

    use super::*;

    // No invalid-response case: the response message is empty, so there is no
    // error contract to prove beyond the shared transport mapping.
    pub fn delete_account_test_cases()
    -> Vec<GrpcTestCase<(), DeleteAccountRequest, DeleteAccountResponse, ()>> {
        let method = "/org.signal.chat.account.Accounts/DeleteAccount";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: DeleteAccountRequest {},
            response_grpc: DeleteAccountResponse {},
            response: (),
        }]
    }

    // The request crosses the bridge as the raw 32-byte SVR key; libsignal derives the registration
    // lock token from it, so the expected gRPC request carries the derived token.
    pub fn set_registration_lock_test_cases()
    -> Vec<GrpcTestCase<[u8; 32], SetRegistrationLockRequest, SetRegistrationLockResponse, ()>>
    {
        let method = "/org.signal.chat.account.Accounts/SetRegistrationLock";
        let svr_key = [0x42; 32];
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: svr_key,
            request_grpc: SetRegistrationLockRequest {
                registration_lock: const_str::hex!(
                    "45b43bb819964ad8ba1c7bcb42a3175eeaf7dd8d2f95728f811517c20dfe72e0"
                )
                .to_vec(),
            },
            response_grpc: SetRegistrationLockResponse {},
            response: (),
        }]
    }

    pub fn clear_registration_lock_test_cases()
    -> Vec<GrpcTestCase<(), ClearRegistrationLockRequest, ClearRegistrationLockResponse, ()>> {
        let method = "/org.signal.chat.account.Accounts/ClearRegistrationLock";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: ClearRegistrationLockRequest {},
            response_grpc: ClearRegistrationLockResponse {},
            response: (),
        }]
    }

    // The request crosses the bridge as the raw 32-byte SVR key; libsignal derives the
    // registration recovery password from it, so the expected gRPC request carries the derived
    // password.
    pub fn set_registration_recovery_password_test_cases() -> Vec<
        GrpcTestCase<
            [u8; 32],
            SetRegistrationRecoveryPasswordRequest,
            SetRegistrationRecoveryPasswordResponse,
            (),
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/SetRegistrationRecoveryPassword";
        let svr_key = [0x42; 32];
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: svr_key,
            request_grpc: SetRegistrationRecoveryPasswordRequest {
                registration_recovery_password: const_str::hex!(
                    "a9fe57f1248e778519606d39502dd27eef87ee03a1fb91963df28dc7107cddca"
                )
                .to_vec(),
            },
            response_grpc: SetRegistrationRecoveryPasswordResponse {},
            response: (),
        }]
    }

    pub fn set_discoverable_by_phone_number_test_cases() -> Vec<
        GrpcTestCase<
            bool,
            SetDiscoverableByPhoneNumberRequest,
            SetDiscoverableByPhoneNumberResponse,
            (),
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/SetDiscoverableByPhoneNumber";
        [true, false]
            .into_iter()
            .map(|discoverable| GrpcTestCase {
                name: if discoverable {
                    "discoverable".to_string()
                } else {
                    "not discoverable".to_string()
                },
                method: method.to_string(),
                request: discoverable,
                request_grpc: SetDiscoverableByPhoneNumberRequest {
                    discoverable_by_phone_number: discoverable,
                },
                response_grpc: SetDiscoverableByPhoneNumberResponse {},
                response: (),
            })
            .collect()
    }

    pub(super) fn test_totp_parameters() -> TotpParameters {
        TotpParameters {
            algorithm: "HmacSHA256".to_string(),
            password_length: 6,
            time_step_seconds: 30,
        }
    }

    pub(super) fn test_totp_parameters_grpc() -> GrpcTotpParameters {
        GrpcTotpParameters {
            algorithm: "HmacSHA256".to_string(),
            password_length: 6,
            time_step_seconds: 30,
        }
    }

    /// The SVR key used to encrypt `test_metadata()` into [`TEST_ENCRYPTED_METADATA`].
    pub const TEST_SVR_KEY: [u8; 32] = [0x42; 32];

    pub(super) fn test_metadata() -> MfaMetadata {
        MfaMetadata::new(
            "Work laptop".to_string(),
            Timestamp::from_epoch_millis(1_782_484_792_000),
        )
        .expect("name fits")
    }

    /// `test_metadata()` encrypted with [`TEST_SVR_KEY`] and an IV taken from a deterministic RNG
    /// seeded with 0 (`crate::api::testutil::fixed_seed_test_rng`). Written out as a literal so the
    /// tests check the actual wire bytes rather than re-deriving them with the code under test.
    pub const TEST_ENCRYPTED_METADATA: [u8; MFA_METADATA_CIPHERTEXT_LEN] = const_str::hex!(
        "b2f7f581d6de3c06a822fd6e7e8265fb967ca8f515bc3d58ed6c8f2b4fcae20d8f8aa3ca02d1865b72e7679cecd4a355c1747b3b7523793178224596f987a49db316c083e963fe7e93c5cc9363f3e7bd8ee577c57b2abe53c9a14606d41ad19646c9e981b01a868d567c27be1b2bdb945979180e56990a2a38b6dc79d4c4283f5e663714cf8f0002ebeb363c50db8cccbd81070e18ad93f7eecaf640dfc50004"
    );

    /// A MAC-valid encrypted metadata protobuf whose name is `before\0after`.
    const TEST_ENCRYPTED_METADATA_WITH_NULL_NAME: [u8; MFA_METADATA_CIPHERTEXT_LEN] = const_str::hex!(
        "b2f7f581d6de3c06a822fd6e7e8265fb52bd8a01eb4655d855889daf63cc5376366fcfe83c35db6db5b6c6c8022255e2ecdee5b3ca0145f6e646446f7503886ad5d12245de1ea1b3daee7cd2526e0d6442da53797aa3bce97284be858e61c79f9b3a6a736bb4923f15f4c2aa55315c8f4f96181fa0aea0cd37f8749a494edc0d7df08588a372f38ed568ef5334b6a8ca5695a3b9d194910cf58d27d64b43e0e4"
    );

    /// A MAC-valid encrypted metadata protobuf whose name contains invalid UTF-8.
    const TEST_ENCRYPTED_METADATA_WITH_INVALID_UTF8: [u8; MFA_METADATA_CIPHERTEXT_LEN] = const_str::hex!(
        "b2f7f581d6de3c06a822fd6e7e8265fb8f3828af4e72e39c4bc815c16cbd5da0b4b5a27311c9326c85c0cc3c1c61c7dd2ff870bf7a7e9b0cd3bb18cd72601695c4a44700541799a0c0d650d04e0dada7d1f2636bb02fd72c17b05d3f69fb1bbcaa09e352f13e2aad070dc7510df212a0cc1c1331de11a82a1454f0412c1eaf2dc897fbc3fd48503d54362047bc068a6f93f1e0b80a6c9a3cd643faeeb045614c"
    );

    pub type GenerateTotpKeyArgs = ();
    pub enum GenerateTotpKeyOut {
        Success(PendingTotpKey),
        TooManyTotpKeys,
        TooManyMfaKeys,
    }
    pub fn generate_totp_key_test_cases() -> Vec<
        GrpcTestCase<
            GenerateTotpKeyArgs,
            GenerateTotpKeyRequest,
            GenerateTotpKeyResponse,
            GenerateTotpKeyOut,
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/GenerateTotpKey";
        let key = b"test TOTP key bytes".to_vec();
        vec![
            GrpcTestCase {
                name: "success".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GenerateTotpKeyRequest {},
                response_grpc: GenerateTotpKeyResponse {
                    response: Some(generate_totp_key_response::Response::KeyGenerated(
                        generate_totp_key_response::KeyGenerated {
                            key: key.clone(),
                            totp_parameters: Some(test_totp_parameters_grpc()),
                        },
                    )),
                },
                response: GenerateTotpKeyOut::Success(PendingTotpKey {
                    key,
                    parameters: test_totp_parameters(),
                }),
            },
            GrpcTestCase {
                name: "too many keys".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GenerateTotpKeyRequest {},
                response_grpc: GenerateTotpKeyResponse {
                    response: Some(generate_totp_key_response::Response::TooManyTotpKeys(
                        Default::default(),
                    )),
                },
                response: GenerateTotpKeyOut::TooManyTotpKeys,
            },
            GrpcTestCase {
                name: "too many MFA keys".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GenerateTotpKeyRequest {},
                response_grpc: GenerateTotpKeyResponse {
                    response: Some(generate_totp_key_response::Response::TooManyMfaKeys(
                        Default::default(),
                    )),
                },
                response: GenerateTotpKeyOut::TooManyMfaKeys,
            },
        ]
    }

    pub struct ConfirmTotpKeyArgs {
        pub one_time_password: u32,
        pub metadata: MfaMetadata,
        pub svr_key: [u8; 32],
    }
    pub enum ConfirmTotpKeyOut {
        Success(MfaKeyId),
        OneTimePasswordNotVerified,
        TooManyMfaKeys,
    }
    pub fn confirm_totp_key_test_cases() -> Vec<
        GrpcTestCase<
            ConfirmTotpKeyArgs,
            ConfirmTotpKeyRequest,
            ConfirmTotpKeyResponse,
            ConfirmTotpKeyOut,
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/ConfirmTotpKey";
        let one_time_password = 123456;
        vec![
            GrpcTestCase {
                name: "success".to_string(),
                method: method.to_string(),
                request: ConfirmTotpKeyArgs {
                    one_time_password,
                    metadata: test_metadata(),
                    svr_key: TEST_SVR_KEY,
                },
                request_grpc: ConfirmTotpKeyRequest {
                    one_time_password,
                    metadata_ciphertext: TEST_ENCRYPTED_METADATA.to_vec(),
                },
                response_grpc: ConfirmTotpKeyResponse {
                    response: Some(confirm_totp_key_response::Response::KeyConfirmed(
                        confirm_totp_key_response::KeyConfirmed { key_id: 17 },
                    )),
                },
                response: ConfirmTotpKeyOut::Success(MfaKeyId(17)),
            },
            GrpcTestCase {
                name: "one-time password not verified".to_string(),
                method: method.to_string(),
                request: ConfirmTotpKeyArgs {
                    one_time_password,
                    metadata: test_metadata(),
                    svr_key: TEST_SVR_KEY,
                },
                request_grpc: ConfirmTotpKeyRequest {
                    one_time_password,
                    metadata_ciphertext: TEST_ENCRYPTED_METADATA.to_vec(),
                },
                response_grpc: ConfirmTotpKeyResponse {
                    response: Some(
                        confirm_totp_key_response::Response::OneTimePasswordNotVerified(
                            Default::default(),
                        ),
                    ),
                },
                response: ConfirmTotpKeyOut::OneTimePasswordNotVerified,
            },
            GrpcTestCase {
                name: "too many MFA keys".to_string(),
                method: method.to_string(),
                request: ConfirmTotpKeyArgs {
                    one_time_password,
                    metadata: test_metadata(),
                    svr_key: TEST_SVR_KEY,
                },
                request_grpc: ConfirmTotpKeyRequest {
                    one_time_password,
                    metadata_ciphertext: TEST_ENCRYPTED_METADATA.to_vec(),
                },
                response_grpc: ConfirmTotpKeyResponse {
                    response: Some(confirm_totp_key_response::Response::TooManyMfaKeys(
                        Default::default(),
                    )),
                },
                response: ConfirmTotpKeyOut::TooManyMfaKeys,
            },
        ]
    }

    pub struct ListMfaKeysArgs {
        pub svr_key: [u8; 32],
    }
    pub enum ListMfaKeysOut {
        Success(Vec<ConfirmedMfaKey>),
    }
    pub fn list_mfa_keys_test_cases()
    -> Vec<GrpcTestCase<ListMfaKeysArgs, ListMfaKeysRequest, ListMfaKeysResponse, ListMfaKeysOut>>
    {
        let method = "/org.signal.chat.account.Accounts/ListMfaKeys";
        let entry = |metadata_ciphertext: Vec<u8>| list_mfa_keys_response::MfaKeyMetadata {
            metadata_ciphertext,
            r#type: GrpcMfaKeyType::Totp as i32,
        };
        let confirmed = |id: u32| ConfirmedMfaKey {
            id: MfaKeyId(id),
            metadata: Ok(test_metadata()),
            kind: MfaKeyKind::Totp,
        };
        let case = |name: &str, keys, expected| GrpcTestCase {
            name: name.to_string(),
            method: method.to_string(),
            request: ListMfaKeysArgs {
                svr_key: TEST_SVR_KEY,
            },
            request_grpc: ListMfaKeysRequest {},
            response_grpc: ListMfaKeysResponse {
                keys: std::collections::HashMap::from_iter(keys),
            },
            response: expected,
        };
        // Any 160-byte blob that doesn't authenticate under TEST_SVR_KEY.
        let unreadable_metadata = vec![0xff; MFA_METADATA_CIPHERTEXT_LEN];
        vec![
            case("no keys", vec![], ListMfaKeysOut::Success(vec![])),
            case(
                "one key",
                vec![(17, entry(TEST_ENCRYPTED_METADATA.to_vec()))],
                ListMfaKeysOut::Success(vec![confirmed(17)]),
            ),
            case(
                "three keys, sorted by ID, including both ends of the ID range",
                vec![
                    (MAX_MFA_KEY_ID, entry(TEST_ENCRYPTED_METADATA.to_vec())),
                    (7, entry(TEST_ENCRYPTED_METADATA.to_vec())),
                    (0, entry(TEST_ENCRYPTED_METADATA.to_vec())),
                ],
                ListMfaKeysOut::Success(vec![
                    confirmed(0),
                    confirmed(7),
                    confirmed(MAX_MFA_KEY_ID),
                ]),
            ),
            // An entry that can't be decrypted is still listed, so the caller can remove it.
            case(
                "unreadable metadata",
                vec![
                    (17, entry(unreadable_metadata)),
                    (18, entry(TEST_ENCRYPTED_METADATA.to_vec())),
                ],
                ListMfaKeysOut::Success(vec![
                    ConfirmedMfaKey {
                        metadata: Err(InvalidMfaMetadata),
                        ..confirmed(17)
                    },
                    confirmed(18),
                ]),
            ),
            // Metadata that authenticates and decrypts, but contains an invalid name, is handled
            // like any other unreadable metadata. The other entry proves it does not fail the list.
            case(
                "metadata name containing NUL",
                vec![
                    (17, entry(TEST_ENCRYPTED_METADATA_WITH_NULL_NAME.to_vec())),
                    (18, entry(TEST_ENCRYPTED_METADATA.to_vec())),
                ],
                ListMfaKeysOut::Success(vec![
                    ConfirmedMfaKey {
                        metadata: Err(InvalidMfaMetadata),
                        ..confirmed(17)
                    },
                    confirmed(18),
                ]),
            ),
            // Protobuf string parsing already rejects invalid UTF-8; keep that rejection on the
            // same per-entry path as other malformed metadata.
            case(
                "metadata name containing invalid UTF-8",
                vec![
                    (
                        17,
                        entry(TEST_ENCRYPTED_METADATA_WITH_INVALID_UTF8.to_vec()),
                    ),
                    (18, entry(TEST_ENCRYPTED_METADATA.to_vec())),
                ],
                ListMfaKeysOut::Success(vec![
                    ConfirmedMfaKey {
                        metadata: Err(InvalidMfaMetadata),
                        ..confirmed(17)
                    },
                    confirmed(18),
                ]),
            ),
            case(
                "wrong-length metadata",
                vec![(17, entry(vec![0xff; MFA_METADATA_CIPHERTEXT_LEN - 1]))],
                ListMfaKeysOut::Success(vec![ConfirmedMfaKey {
                    metadata: Err(InvalidMfaMetadata),
                    ..confirmed(17)
                }]),
            ),
            // A kind of key this version doesn't know about (which decodes as an out-of-range
            // enum value) is still listed, so the caller can remove it.
            case(
                "unknown kind",
                vec![(
                    17,
                    list_mfa_keys_response::MfaKeyMetadata {
                        metadata_ciphertext: TEST_ENCRYPTED_METADATA.to_vec(),
                        r#type: 999,
                    },
                )],
                ListMfaKeysOut::Success(vec![ConfirmedMfaKey {
                    kind: MfaKeyKind::Unknown,
                    ..confirmed(17)
                }]),
            ),
            // Likewise for a server that leaves the type unset.
            case(
                "unspecified kind",
                vec![(
                    17,
                    list_mfa_keys_response::MfaKeyMetadata {
                        metadata_ciphertext: TEST_ENCRYPTED_METADATA.to_vec(),
                        r#type: GrpcMfaKeyType::Unspecified as i32,
                    },
                )],
                ListMfaKeysOut::Success(vec![ConfirmedMfaKey {
                    kind: MfaKeyKind::Unknown,
                    ..confirmed(17)
                }]),
            ),
        ]
    }

    pub struct SetMfaKeyMetadataArgs {
        pub key_id: MfaKeyId,
        pub metadata: MfaMetadata,
        pub svr_key: [u8; 32],
    }
    pub enum SetMfaKeyMetadataOut {
        Success,
        KeyNotFound,
    }
    pub fn set_mfa_key_metadata_test_cases() -> Vec<
        GrpcTestCase<
            SetMfaKeyMetadataArgs,
            SetMfaKeyMetadataRequest,
            SetMfaKeyMetadataResponse,
            SetMfaKeyMetadataOut,
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/SetMfaKeyMetadata";
        vec![
            GrpcTestCase {
                name: "success".to_string(),
                method: method.to_string(),
                request: SetMfaKeyMetadataArgs {
                    key_id: MfaKeyId(17),
                    metadata: test_metadata(),
                    svr_key: TEST_SVR_KEY,
                },
                request_grpc: SetMfaKeyMetadataRequest {
                    key_id: 17,
                    metadata_ciphertext: TEST_ENCRYPTED_METADATA.to_vec(),
                },
                response_grpc: SetMfaKeyMetadataResponse {
                    response: Some(set_mfa_key_metadata_response::Response::MetadataUpdated(
                        set_mfa_key_metadata_response::MetadataUpdated {},
                    )),
                },
                response: SetMfaKeyMetadataOut::Success,
            },
            GrpcTestCase {
                name: "key not found".to_string(),
                method: method.to_string(),
                request: SetMfaKeyMetadataArgs {
                    key_id: MfaKeyId(100),
                    metadata: test_metadata(),
                    svr_key: TEST_SVR_KEY,
                },
                request_grpc: SetMfaKeyMetadataRequest {
                    key_id: 100,
                    metadata_ciphertext: TEST_ENCRYPTED_METADATA.to_vec(),
                },
                response_grpc: SetMfaKeyMetadataResponse {
                    response: Some(set_mfa_key_metadata_response::Response::KeyNotFound(
                        Default::default(),
                    )),
                },
                response: SetMfaKeyMetadataOut::KeyNotFound,
            },
        ]
    }

    pub struct RemoveMfaKeyArgs {
        pub key_id: MfaKeyId,
    }
    pub enum RemoveMfaKeyOut {
        Success,
    }
    pub fn remove_mfa_key_test_cases() -> Vec<
        GrpcTestCase<RemoveMfaKeyArgs, RemoveMfaKeyRequest, RemoveMfaKeyResponse, RemoveMfaKeyOut>,
    > {
        let method = "/org.signal.chat.account.Accounts/RemoveMfaKey";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: RemoveMfaKeyArgs {
                key_id: MfaKeyId(17),
            },
            request_grpc: RemoveMfaKeyRequest { key_id: 17 },
            response_grpc: RemoveMfaKeyResponse {},
            response: RemoveMfaKeyOut::Success,
        }]
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;
    use crate::api::DisconnectedError;
    use crate::api::testutil::fixed_seed_test_rng;
    use crate::grpc::testutil::{err, ok, run_tests, run_tests_with_generic_responses};

    #[test]
    fn test_delete_account() {
        use test_cases::*;
        run_tests(
            delete_account_test_cases(),
            |chat: Auth<_>, ()| async move { chat.delete_account().await },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_set_registration_lock() {
        use test_cases::*;
        run_tests(
            set_registration_lock_test_cases(),
            |chat: Auth<_>, svr_key: [u8; 32]| async move {
                chat.set_registration_lock(SvrKey::new(svr_key)).await
            },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_clear_registration_lock() {
        use test_cases::*;
        run_tests(
            clear_registration_lock_test_cases(),
            |chat: Auth<_>, ()| async move { chat.clear_registration_lock().await },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_set_registration_recovery_password() {
        use test_cases::*;
        run_tests(
            set_registration_recovery_password_test_cases(),
            |chat: Auth<_>, svr_key: [u8; 32]| async move {
                let registration_recovery_password =
                    SvrKey::new(svr_key).derive_registration_recovery_password();
                chat.set_registration_recovery_password(registration_recovery_password)
                    .await
            },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_set_registration_recovery_password_from_svr_key() {
        use test_cases::*;
        run_tests(
            set_registration_recovery_password_test_cases(),
            |chat: Auth<_>, svr_key: [u8; 32]| async move {
                chat.set_registration_recovery_password_from_svr_key(SvrKey::new(svr_key))
                    .await
            },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_set_discoverable_by_phone_number() {
        use test_cases::*;
        run_tests(
            set_discoverable_by_phone_number_test_cases(),
            |chat: Auth<_>, discoverable: bool| async move {
                chat.set_discoverable_by_phone_number(discoverable).await
            },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_generate_totp_key() {
        use test_cases::*;
        run_tests(
            generate_totp_key_test_cases(),
            |chat: Auth<_>, ()| async move { chat.generate_totp_key().await },
            |resp, result| match resp {
                GenerateTotpKeyOut::Success(pending) => {
                    assert_eq!(pending, result.expect("success"))
                }
                GenerateTotpKeyOut::TooManyTotpKeys => {
                    assert_matches!(
                        result,
                        Err(RequestError::Other(GenerateTotpKeyError::TooManyTotpKeys))
                    )
                }
                GenerateTotpKeyOut::TooManyMfaKeys => {
                    assert_matches!(
                        result,
                        Err(RequestError::Other(GenerateTotpKeyError::TooManyMfaKeys))
                    )
                }
            },
        );
    }

    #[test]
    fn test_generate_totp_key_invalid_responses() {
        let case = |name: &str, response_grpc, is_disconnect: bool| GrpcTestCase {
            name: name.to_string(),
            method: "/org.signal.chat.account.Accounts/GenerateTotpKey".to_string(),
            request: (),
            request_grpc: GenerateTotpKeyRequest {},
            response_grpc,
            response: is_disconnect,
        };
        run_tests_with_generic_responses(
            [
                case(
                    "missing response",
                    ok(GenerateTotpKeyResponse { response: None }),
                    false,
                ),
                case(
                    "missing TOTP parameters",
                    ok(GenerateTotpKeyResponse {
                        response: Some(generate_totp_key_response::Response::KeyGenerated(
                            generate_totp_key_response::KeyGenerated {
                                key: b"test TOTP key bytes".to_vec(),
                                totp_parameters: None,
                            },
                        )),
                    }),
                    false,
                ),
                case(
                    "unreasonably large TOTP parameters",
                    ok(GenerateTotpKeyResponse {
                        response: Some(generate_totp_key_response::Response::KeyGenerated(
                            generate_totp_key_response::KeyGenerated {
                                key: b"test TOTP key bytes".to_vec(),
                                totp_parameters: Some(GrpcTotpParameters {
                                    password_length: u32::MAX,
                                    ..test_cases::test_totp_parameters_grpc()
                                }),
                            },
                        )),
                    }),
                    false,
                ),
                case(
                    "zero-valued TOTP parameters",
                    ok(GenerateTotpKeyResponse {
                        response: Some(generate_totp_key_response::Response::KeyGenerated(
                            generate_totp_key_response::KeyGenerated {
                                key: b"test TOTP key bytes".to_vec(),
                                totp_parameters: Some(GrpcTotpParameters {
                                    time_step_seconds: 0,
                                    ..test_cases::test_totp_parameters_grpc()
                                }),
                            },
                        )),
                    }),
                    false,
                ),
                case("grpc error", err(tonic::Code::Internal), true),
            ],
            |chat: Auth<_>, ()| async move { chat.generate_totp_key().await },
            |is_disconnect, result| {
                if is_disconnect {
                    assert_matches!(
                        result,
                        Err(RequestError::Disconnected(
                            DisconnectedError::Transport { .. }
                        ))
                    )
                } else {
                    assert_matches!(result, Err(RequestError::Unexpected { .. }))
                }
            },
        );
    }

    #[test]
    fn test_encrypted_metadata_literal_matches_fixed_seed_rng() {
        let encrypted = test_cases::test_metadata().encrypt(
            &SvrKey::new(test_cases::TEST_SVR_KEY),
            &mut fixed_seed_test_rng(),
        );
        assert_eq!(
            *encrypted.as_bytes(),
            test_cases::TEST_ENCRYPTED_METADATA,
            "expected (hex) {}",
            hex::encode(encrypted.as_bytes())
        );
    }

    #[test]
    fn test_confirm_totp_key() {
        use test_cases::*;
        run_tests(
            confirm_totp_key_test_cases(),
            |chat: Auth<_>,
             ConfirmTotpKeyArgs {
                 one_time_password,
                 metadata,
                 svr_key,
             }| async move {
                chat.confirm_totp_key(
                    one_time_password,
                    &metadata,
                    &SvrKey::new(svr_key),
                    &mut fixed_seed_test_rng(),
                )
                .await
            },
            |resp, result| match resp {
                ConfirmTotpKeyOut::Success(key_id) => {
                    assert_matches!(result, Ok(x) if x == key_id)
                }
                ConfirmTotpKeyOut::OneTimePasswordNotVerified => {
                    assert_matches!(
                        result,
                        Err(RequestError::Other(
                            ConfirmTotpKeyError::OneTimePasswordNotVerified
                        ))
                    )
                }
                ConfirmTotpKeyOut::TooManyMfaKeys => {
                    assert_matches!(
                        result,
                        Err(RequestError::Other(ConfirmTotpKeyError::TooManyMfaKeys))
                    )
                }
            },
        );
    }

    #[test]
    fn test_confirm_totp_key_invalid_responses() {
        let case = |name: &str, response_grpc, is_disconnect: bool| GrpcTestCase {
            name: name.to_string(),
            method: "/org.signal.chat.account.Accounts/ConfirmTotpKey".to_string(),
            request: (),
            request_grpc: ConfirmTotpKeyRequest {
                one_time_password: 123456,
                metadata_ciphertext: test_cases::TEST_ENCRYPTED_METADATA.to_vec(),
            },
            response_grpc,
            response: is_disconnect,
        };
        run_tests_with_generic_responses(
            [
                case(
                    "missing response",
                    ok(ConfirmTotpKeyResponse { response: None }),
                    false,
                ),
                case(
                    "key ID out of range",
                    ok(ConfirmTotpKeyResponse {
                        response: Some(confirm_totp_key_response::Response::KeyConfirmed(
                            confirm_totp_key_response::KeyConfirmed {
                                key_id: MAX_MFA_KEY_ID + 1,
                            },
                        )),
                    }),
                    false,
                ),
                case("grpc error", err(tonic::Code::Internal), true),
            ],
            |chat: Auth<_>, ()| async move {
                chat.confirm_totp_key(
                    123456,
                    &test_cases::test_metadata(),
                    &SvrKey::new(test_cases::TEST_SVR_KEY),
                    &mut fixed_seed_test_rng(),
                )
                .await
            },
            |is_disconnect, result| {
                if is_disconnect {
                    assert_matches!(
                        result,
                        Err(RequestError::Disconnected(
                            DisconnectedError::Transport { .. }
                        ))
                    )
                } else {
                    assert_matches!(result, Err(RequestError::Unexpected { .. }))
                }
            },
        );
    }

    #[test]
    fn test_list_mfa_keys() {
        use test_cases::*;
        run_tests(
            list_mfa_keys_test_cases(),
            |chat: Auth<_>, ListMfaKeysArgs { svr_key }| async move {
                chat.list_mfa_keys(&SvrKey::new(svr_key)).await
            },
            |resp, result| match resp {
                ListMfaKeysOut::Success(keys) => assert_eq!(keys, result.expect("success")),
            },
        );
    }

    #[test]
    fn test_list_mfa_keys_invalid_responses() {
        let method = "/org.signal.chat.account.Accounts/ListMfaKeys";
        let case = |name: &str, response_grpc, is_disconnect: bool| GrpcTestCase {
            name: name.to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: ListMfaKeysRequest {},
            response_grpc,
            response: is_disconnect,
        };
        run_tests_with_generic_responses(
            [
                case(
                    "key ID out of range",
                    ok(ListMfaKeysResponse {
                        keys: std::collections::HashMap::from([(
                            MAX_MFA_KEY_ID + 1,
                            list_mfa_keys_response::MfaKeyMetadata {
                                metadata_ciphertext: test_cases::TEST_ENCRYPTED_METADATA.to_vec(),
                                r#type: GrpcMfaKeyType::Totp as i32,
                            },
                        )]),
                    }),
                    false,
                ),
                case("grpc error", err(tonic::Code::Internal), true),
            ],
            |chat: Auth<_>, ()| async move {
                chat.list_mfa_keys(&SvrKey::new(test_cases::TEST_SVR_KEY))
                    .await
            },
            |is_disconnect, result| {
                if is_disconnect {
                    assert_matches!(
                        result,
                        Err(RequestError::Disconnected(
                            DisconnectedError::Transport { .. }
                        ))
                    )
                } else {
                    assert_matches!(result, Err(RequestError::Unexpected { .. }))
                }
            },
        );
    }

    #[test]
    fn test_set_mfa_key_metadata() {
        use test_cases::*;
        run_tests(
            set_mfa_key_metadata_test_cases(),
            |chat: Auth<_>,
             SetMfaKeyMetadataArgs {
                 key_id,
                 metadata,
                 svr_key,
             }| async move {
                chat.set_mfa_key_metadata(
                    key_id,
                    &metadata,
                    &SvrKey::new(svr_key),
                    &mut fixed_seed_test_rng(),
                )
                .await
            },
            |resp, result| match resp {
                SetMfaKeyMetadataOut::Success => assert_matches!(result, Ok(())),
                SetMfaKeyMetadataOut::KeyNotFound => {
                    assert_matches!(result, Err(RequestError::Other(MfaKeyNotFound)))
                }
            },
        );
    }

    #[test]
    fn test_set_mfa_key_metadata_invalid_responses() {
        let case = |name: &str, response_grpc, is_disconnect: bool| GrpcTestCase {
            name: name.to_string(),
            method: "/org.signal.chat.account.Accounts/SetMfaKeyMetadata".to_string(),
            request: (),
            request_grpc: SetMfaKeyMetadataRequest {
                key_id: 17,
                metadata_ciphertext: test_cases::TEST_ENCRYPTED_METADATA.to_vec(),
            },
            response_grpc,
            response: is_disconnect,
        };
        run_tests_with_generic_responses(
            [
                case(
                    "missing response",
                    ok(SetMfaKeyMetadataResponse { response: None }),
                    false,
                ),
                case("grpc error", err(tonic::Code::Internal), true),
            ],
            |chat: Auth<_>, ()| async move {
                chat.set_mfa_key_metadata(
                    MfaKeyId(17),
                    &test_cases::test_metadata(),
                    &SvrKey::new(test_cases::TEST_SVR_KEY),
                    &mut fixed_seed_test_rng(),
                )
                .await
            },
            |is_disconnect, result| {
                if is_disconnect {
                    assert_matches!(
                        result,
                        Err(RequestError::Disconnected(
                            DisconnectedError::Transport { .. }
                        ))
                    )
                } else {
                    assert_matches!(result, Err(RequestError::Unexpected { .. }))
                }
            },
        );
    }

    #[test]
    fn test_remove_mfa_key() {
        use test_cases::*;
        run_tests(
            remove_mfa_key_test_cases(),
            |chat: Auth<_>, RemoveMfaKeyArgs { key_id }| async move {
                chat.remove_mfa_key(key_id).await
            },
            |resp, result| match resp {
                RemoveMfaKeyOut::Success => assert_matches!(result, Ok(())),
            },
        );
    }

    #[test]
    fn test_remove_mfa_key_invalid_responses() {
        run_tests_with_generic_responses(
            [GrpcTestCase {
                name: "grpc error".to_string(),
                method: "/org.signal.chat.account.Accounts/RemoveMfaKey".to_string(),
                request: (),
                request_grpc: RemoveMfaKeyRequest { key_id: 17 },
                response_grpc: err(tonic::Code::Internal),
                response: (),
            }],
            |chat: Auth<_>, ()| async move { chat.remove_mfa_key(MfaKeyId(17)).await },
            |(), result| {
                assert_matches!(
                    result,
                    Err(RequestError::Disconnected(
                        DisconnectedError::Transport { .. }
                    ))
                )
            },
        );
    }
}
