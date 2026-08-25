//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use displaydoc::Display;
use libsignal_core::Aci;
use libsignal_net_grpc::proto::chat::account::accounts_anonymous_client::AccountsAnonymousClient;
use libsignal_net_grpc::proto::chat::account::accounts_client::AccountsClient;
use libsignal_net_grpc::proto::chat::account::confirm_username_hash_response::{
    ConfirmedUsernameHash, Response as ConfirmUsernameResponse,
};
use libsignal_net_grpc::proto::chat::account::*;
use libsignal_net_grpc::proto::chat::errors;
use uuid::Uuid;

use super::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::api::usernames::validate_username_from_link;
use crate::api::{Auth, RequestError, Unauth};
use crate::logging::{Redact, RedactHex};

pub type UsernameHash = [u8; 32];
#[derive(Debug, Display)]
/// None of the candidate usernames were available.
pub struct UsernameNotAvailable;

#[derive(Debug, Display)]
/// The authenticated account did not have a username set.
pub struct UsernameNotSet;

/// Recoverable errors produced by [`Auth::confirm_username`].
#[derive(Debug, Display)]
pub enum ConfirmUsernameError {
    /// The username hash was not reserved for this account.
    ReservationNotFound,
    /// The reservation lapsed and the username was claimed by another account.
    UsernameNotAvailable,
}

impl std::fmt::Display for Redact<ReserveUsernameHashRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(ReserveUsernameHashRequest { username_hashes }) = self;
        f.debug_struct("ReserveUsernameHash")
            .field("username_hashes.len", &username_hashes.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<ConfirmUsernameHashRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(ConfirmUsernameHashRequest {
            username_hash,
            zk_proof,
            username_ciphertext,
        }) = self;
        f.debug_struct("ConfirmUsernameHash")
            .field("username_hash.len", &username_hash.len())
            .field("zk_proof.len", &zk_proof.len())
            .field("username_ciphertext.len", &username_ciphertext.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<SetUsernameLinkRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetUsernameLinkRequest {
            username_ciphertext,
            keep_link_handle,
        }) = self;
        f.debug_struct("SetUsernameLinkRequest")
            .field("username_ciphertext.len", &username_ciphertext.len())
            .field("keep_link_handle", &keep_link_handle)
            .finish()
    }
}

impl std::fmt::Display for Redact<DeleteUsernameHashRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(DeleteUsernameHashRequest {}) = self;
        f.debug_struct("DeleteUsernameHashRequest").finish()
    }
}

impl std::fmt::Display for Redact<DeleteUsernameLinkRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(DeleteUsernameLinkRequest {}) = self;
        f.debug_struct("DeleteUsernameLinkRequest").finish()
    }
}

pub type UsernameLinkHandle = Uuid;

impl<T: GrpcServiceProvider> Auth<T> {
    /// Given a prioritized list of between 1 and 20 username hashes, try reserving them (in order)
    ///
    /// The first successfully reserved hash will be returned.
    pub async fn reserve_username_hash(
        &self,
        username_hashes: &[UsernameHash],
    ) -> Result<UsernameHash, RequestError<UsernameNotAvailable>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = ReserveUsernameHashRequest {
            username_hashes: username_hashes.iter().map(|hash| hash.to_vec()).collect(),
        };
        let desc = Redact(&request).to_string();
        match log_and_send("auth", &desc, || client.reserve_username_hash(request))
            .await?
            .into_inner()
            .response
            .ok_or_else(|| RequestError::Unexpected {
                log_safe: "missing response".to_string(),
            })? {
            reserve_username_hash_response::Response::UsernameHash(hash) => {
                let hash_len = hash.len();
                UsernameHash::try_from(hash).map_err(|_| RequestError::Unexpected {
                    log_safe: format!("Expected 32 byte username hash; got {}", hash_len),
                })
            }
            reserve_username_hash_response::Response::UsernameNotAvailable(
                libsignal_net_grpc::proto::chat::account::UsernameNotAvailable {},
            ) => Err(RequestError::Other(UsernameNotAvailable)),
        }
    }

    /// Sets the account's username to a previously-reserved value (see
    /// [`Auth::reserve_username_hash`]), along with the encrypted username for the account's
    /// username link.
    ///
    /// The zero-knowledge proof that must accompany the username hash is generated internally.
    /// Returns the server-generated username link handle for the newly-confirmed username.
    ///
    /// `username_ciphertext` must be between 1 and 128 bytes.
    pub async fn confirm_username(
        &self,
        username: &usernames::Username,
        username_ciphertext: Vec<u8>,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<UsernameLinkHandle, RequestError<ConfirmUsernameError>> {
        let mut randomness = [0; 32];
        rng.fill_bytes(&mut randomness);
        let zk_proof = username
            .proof(&randomness)
            // usernames actually panics rather than returning errors anyway, so
            // our hands are tied
            .expect("proof generation should never fail for a valid username");

        let mut client = AccountsClient::new(self.0.service());
        let request = ConfirmUsernameHashRequest {
            username_hash: username.hash().to_vec(),
            zk_proof,
            username_ciphertext,
        };
        let desc = Redact(&request).to_string();
        let response = log_and_send("auth", &desc, || client.confirm_username_hash(request))
            .await?
            .into_inner()
            .response
            .ok_or_else(|| RequestError::Unexpected {
                log_safe: "missing response".to_string(),
            })?;

        match response {
            ConfirmUsernameResponse::ReservationNotFound(errors::FailedPrecondition {
                description,
            }) => {
                log::warn!("username reservation not found: {description}");
                Err(RequestError::Other(
                    ConfirmUsernameError::ReservationNotFound,
                ))
            }
            ConfirmUsernameResponse::UsernameNotAvailable(
                libsignal_net_grpc::proto::chat::account::UsernameNotAvailable {},
            ) => Err(RequestError::Other(
                ConfirmUsernameError::UsernameNotAvailable,
            )),
            ConfirmUsernameResponse::ConfirmedUsernameHash(ConfirmedUsernameHash {
                username_link_handle,
            }) => {
                // If the returned username_link_handle does not parse as a UUID, we assume that is
                // a bad enough sign to invalidate the response and treat it as Unexpected.
                Uuid::from_slice(&username_link_handle).map_err(|_| RequestError::Unexpected {
                    log_safe: "invalid uuid".to_string(),
                })
            }
        }
    }

    /// For the given encrypted username, generate a username link handle. The username link handle
    /// can be used to lookup the encrypted username.
    ///
    /// An account can only have one username link at a time; this endpoint overwrites the previous
    /// encrypted username if there was one.
    ///
    /// `username_ciphertext` must be between 1 and 128 bytes.
    pub async fn set_username_link(
        &self,
        username_ciphertext: &[u8],
        keep_link_handle: bool,
    ) -> Result<UsernameLinkHandle, RequestError<UsernameNotSet>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = SetUsernameLinkRequest {
            username_ciphertext: username_ciphertext.to_vec(),
            keep_link_handle,
        };
        let desc = Redact(&request).to_string();
        match log_and_send("auth", &desc, || client.set_username_link(request))
            .await?
            .into_inner()
            .response
            .ok_or_else(|| RequestError::Unexpected {
                log_safe: "missing response".to_string(),
            })? {
            set_username_link_response::Response::UsernameLinkHandle(username_link_handle) => {
                Uuid::from_slice(&username_link_handle).map_err(|_| RequestError::Unexpected {
                    log_safe: "invalid uuid".to_string(),
                })
            }
            set_username_link_response::Response::NoUsernameSet(_) => {
                Err(RequestError::Other(UsernameNotSet))
            }
        }
    }

    /// Clears the current username hash, ciphertext, and link for the authenticated account.
    ///
    /// This also succeeds if the account has no username set, so a caller retrying a deletion
    /// sees the same result as the original call.
    pub async fn delete_username_hash(&self) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = DeleteUsernameHashRequest {};
        let desc = Redact(&request).to_string();
        let DeleteUsernameHashResponse {} =
            log_and_send("auth", &desc, || client.delete_username_hash(request))
                .await?
                .into_inner();
        Ok(())
    }

    /// Clears any username link associated with the authenticated account.
    ///
    /// The previously stored encrypted username is deleted and the link handle is deactivated;
    /// the account's username hash (if any) is left in place. This also succeeds if the account
    /// has no username link, so a caller retrying a deletion sees the same result as the
    /// original call.
    pub async fn delete_username_link(&self) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = DeleteUsernameLinkRequest {};
        let desc = Redact(&request).to_string();
        let DeleteUsernameLinkResponse {} =
            log_and_send("auth", &desc, || client.delete_username_link(request))
                .await?
                .into_inner();
        Ok(())
    }
}

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::usernames::UnauthenticatedChatApi<OverGrpc> for Unauth<T> {
    async fn look_up_username_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<Aci>, RequestError<Infallible>> {
        let mut account_service = AccountsAnonymousClient::new(self.0.service());
        let request = LookupUsernameHashRequest {
            username_hash: hash.into(),
        };
        let log_safe_description = Redact(&request).to_string();
        let LookupUsernameHashResponse { response } =
            log_and_send("unauth", &log_safe_description, || {
                account_service.lookup_username_hash(request)
            })
            .await?
            .into_inner();

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        let id = match response {
            lookup_username_hash_response::Response::ServiceIdentifier(service_id) => service_id,
            lookup_username_hash_response::Response::NotFound(errors::NotFound {}) => {
                return Ok(None);
            }
        }
        .try_as_service_id()
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "unable to parse service ID in response".to_owned(),
        })?;

        let aci = Aci::try_from(id).map_err(|_| RequestError::Unexpected {
            log_safe: format!("lookup returned {} instead of ACI", id.kind()),
        })?;

        Ok(Some(aci))
    }

    async fn look_up_username_link(
        &self,
        uuid: uuid::Uuid,
        entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, RequestError<usernames::UsernameLinkError>> {
        let mut account_service = AccountsAnonymousClient::new(self.0.service());
        let request = LookupUsernameLinkRequest {
            username_link_handle: uuid.as_bytes().to_vec(),
        };
        let log_safe_description = Redact(&request).to_string();
        let LookupUsernameLinkResponse { response } =
            log_and_send("unauth", &log_safe_description, || {
                account_service.lookup_username_link(request)
            })
            .await?
            .into_inner();

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        let encrypted_username = match response {
            lookup_username_link_response::Response::UsernameCiphertext(ciphertext) => ciphertext,
            lookup_username_link_response::Response::NotFound(errors::NotFound {}) => {
                return Ok(None);
            }
        };

        let plaintext_username = usernames::decrypt_username(entropy, &encrypted_username)
            .map_err(RequestError::Other)?;

        let validated_username = validate_username_from_link(&plaintext_username)?;

        Ok(Some(validated_username))
    }
}

impl std::fmt::Display for Redact<LookupUsernameHashRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(LookupUsernameHashRequest { username_hash }) = self;
        f.debug_struct("LookupUsernameHash")
            .field("username_hash", &RedactHex(&hex::encode(username_hash)))
            .finish()
    }
}

impl std::fmt::Display for Redact<LookupUsernameLinkRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(LookupUsernameLinkRequest {
            username_link_handle,
        }) = self;
        f.debug_struct("LookupUsernameLink")
            .field(
                "username_link_handle",
                &uuid::Uuid::from_slice(username_link_handle)
                    .ok()
                    .map(Redact),
            )
            .finish()
    }
}

pub mod test_cases {
    use data_encoding_macro::base64url_nopad;

    use super::*;
    use crate::grpc::GrpcTestCase;

    pub(super) const ENCRYPTED_USERNAME: &[u8] = &base64url_nopad!(
        "kj5ah-VbEgjpfJsNt-Wto2H626DRmJSVpYPy0yPOXA8kiSFkBCD8ysFlJ-Z3MhiAnt_R3Nm7ZY0W5fiRDLVbhaE2z-KO2xdf5NcVbkewCzhvveecS3hHskDp1aSfbvwTZNNGPmAuKWvJ1MPdHzsF0w"
    );
    pub(super) const ENCRYPTED_USERNAME_ENTROPY: [u8;
        usernames::constants::USERNAME_LINK_ENTROPY_SIZE] =
        const_str::hex!("4302c613c092a51c5394becffeb6f697300a605348e93f03c3db95e0b03d28f1");

    pub struct LookUpUsernameLinkArgs {
        pub uuid: uuid::Uuid,
        pub entropy: [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    }

    pub enum LookUpUsernameLinkOut {
        Success(String),
        NotFound,
        LinkDataTooShort,
        MissingResponse,
    }

    pub fn look_up_username_link_test_cases() -> Vec<
        GrpcTestCase<
            LookUpUsernameLinkArgs,
            LookupUsernameLinkRequest,
            LookupUsernameLinkResponse,
            LookUpUsernameLinkOut,
        >,
    > {
        let uuid = uuid::uuid!("f63364ab-5d53-4300-93d8-3f38ff26af98");
        let method = "/org.signal.chat.account.AccountsAnonymous/LookupUsernameLink";
        vec![
            GrpcTestCase {
                name: "success".to_string(),
                method: method.to_string(),
                request: LookUpUsernameLinkArgs {
                    uuid,
                    entropy: ENCRYPTED_USERNAME_ENTROPY,
                },
                request_grpc: LookupUsernameLinkRequest {
                    username_link_handle: uuid.as_bytes().to_vec(),
                },
                response_grpc: LookupUsernameLinkResponse {
                    response: Some(lookup_username_link_response::Response::UsernameCiphertext(
                        ENCRYPTED_USERNAME.to_vec(),
                    )),
                },
                response: LookUpUsernameLinkOut::Success(TEST_USERNAME.to_owned()),
            },
            GrpcTestCase {
                name: "not found".to_string(),
                method: method.to_string(),
                request: LookUpUsernameLinkArgs {
                    uuid,
                    entropy: ENCRYPTED_USERNAME_ENTROPY,
                },
                request_grpc: LookupUsernameLinkRequest {
                    username_link_handle: uuid.as_bytes().to_vec(),
                },
                response_grpc: LookupUsernameLinkResponse {
                    response: Some(lookup_username_link_response::Response::NotFound(
                        Default::default(),
                    )),
                },
                response: LookUpUsernameLinkOut::NotFound,
            },
            GrpcTestCase {
                name: "data too short".to_string(),
                method: method.to_string(),
                request: LookUpUsernameLinkArgs {
                    uuid,
                    entropy: ENCRYPTED_USERNAME_ENTROPY,
                },
                request_grpc: LookupUsernameLinkRequest {
                    username_link_handle: uuid.as_bytes().to_vec(),
                },
                response_grpc: LookupUsernameLinkResponse {
                    response: Some(lookup_username_link_response::Response::UsernameCiphertext(
                        b"!garbage!".to_vec(),
                    )),
                },
                response: LookUpUsernameLinkOut::LinkDataTooShort,
            },
            GrpcTestCase {
                name: "missing response".to_string(),
                method: method.to_string(),
                request: LookUpUsernameLinkArgs {
                    uuid,
                    entropy: ENCRYPTED_USERNAME_ENTROPY,
                },
                request_grpc: LookupUsernameLinkRequest {
                    username_link_handle: uuid.as_bytes().to_vec(),
                },
                response_grpc: LookupUsernameLinkResponse { response: None },
                response: LookUpUsernameLinkOut::MissingResponse,
            },
        ]
    }
    pub struct ReserveUsernameHashArgs {
        pub usernames: Vec<UsernameHash>,
    }
    pub enum ReserveUsernameHashOut {
        Success(UsernameHash),
        UsernameNotAvailable,
    }
    pub fn reserve_username_hash_test_cases() -> Vec<
        GrpcTestCase<
            ReserveUsernameHashArgs,
            ReserveUsernameHashRequest,
            ReserveUsernameHashResponse,
            ReserveUsernameHashOut,
        >,
    > {
        let hash0 = *b"................................";
        let hash1 = *b"++++++++++++++++++++++++++++++++";
        let method = "/org.signal.chat.account.Accounts/ReserveUsernameHash";
        vec![
            GrpcTestCase {
                name: "success".to_string(),
                method: method.to_string(),
                request: ReserveUsernameHashArgs {
                    usernames: vec![hash0, hash1],
                },
                request_grpc: ReserveUsernameHashRequest {
                    username_hashes: vec![hash0.to_vec(), hash1.to_vec()],
                },
                response_grpc: ReserveUsernameHashResponse {
                    response: Some(reserve_username_hash_response::Response::UsernameHash(
                        hash0.to_vec(),
                    )),
                },
                response: ReserveUsernameHashOut::Success(hash0),
            },
            GrpcTestCase {
                name: "failed to reserve username".to_string(),
                method: method.to_string(),
                request: ReserveUsernameHashArgs {
                    usernames: vec![hash0, hash1],
                },
                request_grpc: ReserveUsernameHashRequest {
                    username_hashes: vec![hash0.to_vec(), hash1.to_vec()],
                },
                response_grpc: ReserveUsernameHashResponse {
                    response: Some(
                        reserve_username_hash_response::Response::UsernameNotAvailable(
                            Default::default(),
                        ),
                    ),
                },
                response: ReserveUsernameHashOut::UsernameNotAvailable,
            },
        ]
    }
    /// The username used in [`confirm_username_test_cases`], and the plaintext of
    /// `ENCRYPTED_USERNAME` in [`look_up_username_link_test_cases`].
    pub const TEST_USERNAME: &str = "moxie.01";

    /// A test ACI, matching the value used in the gRPC profiles tests.
    pub const ACI_UUID: Uuid = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");

    /// A placeholder encrypted username used in the confirm/set-link test cases.
    pub const TEST_USERNAME_CIPHERTEXT: &[u8] = b"fun encrypted username";

    /// The gRPC method path for `ConfirmUsernameHash`.
    pub const CONFIRM_USERNAME_HASH_METHOD: &str =
        "/org.signal.chat.account.Accounts/ConfirmUsernameHash";

    /// The expected proof for [`TEST_USERNAME`], generated with 32 bytes of randomness taken from
    /// crate::api::testutil::fixed_seed_test_rng (i.e. a deterministic RNG with seed 0).
    pub(crate) const EXPECTED_TEST_PROOF: &[u8] = &data_encoding_macro::base64!(
        "gpplBfu0UNhHs9/BSYIf1/y9G4EEEg8D02nw79nt/gTcUj1isL6KJlydRYI9+CdDcMS2+jl7f2KqPvRyy6mxAktWpipDNJcwyhng+hdeEIfVfE4ziksMYhApMkQbo6kBi+fNCVSy6BA3SlCC1GVHtOdggnLy3u1ffojmupc3rgk="
    );

    pub struct ConfirmUsernameArgs {
        pub username: String,
        pub username_ciphertext: Vec<u8>,
    }
    pub enum ConfirmUsernameOut {
        Success(UsernameLinkHandle),
        ReservationNotFound,
        UsernameNotAvailable,
    }
    pub fn confirm_username_test_cases() -> Vec<
        GrpcTestCase<
            ConfirmUsernameArgs,
            ConfirmUsernameHashRequest,
            ConfirmUsernameHashResponse,
            ConfirmUsernameOut,
        >,
    > {
        let username_hash = usernames::Username::new(TEST_USERNAME)
            .expect("valid username")
            .hash();
        let username_link_handle = uuid::uuid!("61c101a5-04d8-4217-a6b9-a3f5c6e25b29");

        let case = |name: &str,
                    grpc_response: ConfirmUsernameResponse,
                    expected_ret: ConfirmUsernameOut| GrpcTestCase {
            name: name.to_string(),
            method: CONFIRM_USERNAME_HASH_METHOD.to_string(),
            request: ConfirmUsernameArgs {
                username: TEST_USERNAME.to_string(),
                username_ciphertext: TEST_USERNAME_CIPHERTEXT.to_vec(),
            },
            request_grpc: ConfirmUsernameHashRequest {
                username_hash: username_hash.to_vec(),
                zk_proof: EXPECTED_TEST_PROOF.to_vec(),
                username_ciphertext: TEST_USERNAME_CIPHERTEXT.to_vec(),
            },
            response_grpc: ConfirmUsernameHashResponse {
                response: Some(grpc_response),
            },
            response: expected_ret,
        };

        vec![
            case(
                "success",
                ConfirmUsernameResponse::ConfirmedUsernameHash(ConfirmedUsernameHash {
                    username_link_handle: username_link_handle.into(),
                }),
                ConfirmUsernameOut::Success(username_link_handle),
            ),
            case(
                "reservation not found",
                ConfirmUsernameResponse::ReservationNotFound(Default::default()),
                ConfirmUsernameOut::ReservationNotFound,
            ),
            case(
                "username not available",
                ConfirmUsernameResponse::UsernameNotAvailable(Default::default()),
                ConfirmUsernameOut::UsernameNotAvailable,
            ),
        ]
    }
    pub struct SetUsernameLinkArgs {
        pub username_ciphertext: Vec<u8>,
        pub keep_link_handle: bool,
    }
    pub enum SetUsernameLinkOut {
        Success(UsernameLinkHandle),
        UsernameNotSet,
    }
    pub fn set_username_link_test_cases() -> Vec<
        GrpcTestCase<
            SetUsernameLinkArgs,
            SetUsernameLinkRequest,
            SetUsernameLinkResponse,
            SetUsernameLinkOut,
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/SetUsernameLink";
        let username_ciphertext = TEST_USERNAME_CIPHERTEXT.to_vec();
        let username_link_handle = uuid::uuid!("C525F4F7-AF58-47CC-936E-D1B717F3C50A");
        vec![
            GrpcTestCase {
                name: "success, keep_link_handle".to_string(),
                method: method.to_string(),
                request: SetUsernameLinkArgs {
                    username_ciphertext: username_ciphertext.clone(),
                    keep_link_handle: true,
                },
                request_grpc: SetUsernameLinkRequest {
                    username_ciphertext: username_ciphertext.clone(),
                    keep_link_handle: true,
                },
                response_grpc: SetUsernameLinkResponse {
                    response: Some(set_username_link_response::Response::UsernameLinkHandle(
                        username_link_handle.into(),
                    )),
                },
                response: SetUsernameLinkOut::Success(username_link_handle),
            },
            GrpcTestCase {
                name: "success, no keep_link_handle".to_string(),
                method: method.to_string(),
                request: SetUsernameLinkArgs {
                    username_ciphertext: username_ciphertext.clone(),
                    keep_link_handle: false,
                },
                request_grpc: SetUsernameLinkRequest {
                    username_ciphertext: username_ciphertext.clone(),
                    keep_link_handle: false,
                },
                response_grpc: SetUsernameLinkResponse {
                    response: Some(set_username_link_response::Response::UsernameLinkHandle(
                        username_link_handle.into(),
                    )),
                },
                response: SetUsernameLinkOut::Success(username_link_handle),
            },
            GrpcTestCase {
                name: "failure, no keep_link_handle".to_string(),
                method: method.to_string(),
                request: SetUsernameLinkArgs {
                    username_ciphertext: username_ciphertext.clone(),
                    keep_link_handle: false,
                },
                request_grpc: SetUsernameLinkRequest {
                    username_ciphertext: username_ciphertext.clone(),
                    keep_link_handle: false,
                },
                response_grpc: SetUsernameLinkResponse {
                    response: Some(set_username_link_response::Response::NoUsernameSet(
                        Default::default(),
                    )),
                },
                response: SetUsernameLinkOut::UsernameNotSet,
            },
        ]
    }
    pub type DeleteUsernameHashArgs = ();
    pub type DeleteUsernameHashOut = ();
    pub fn delete_username_hash_test_cases() -> Vec<
        GrpcTestCase<
            DeleteUsernameHashArgs,
            DeleteUsernameHashRequest,
            DeleteUsernameHashResponse,
            DeleteUsernameHashOut,
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/DeleteUsernameHash";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: DeleteUsernameHashRequest {},
            response_grpc: DeleteUsernameHashResponse {},
            response: (),
        }]
    }
    pub type DeleteUsernameLinkArgs = ();
    pub type DeleteUsernameLinkOut = ();
    pub fn delete_username_link_test_cases() -> Vec<
        GrpcTestCase<
            DeleteUsernameLinkArgs,
            DeleteUsernameLinkRequest,
            DeleteUsernameLinkResponse,
            DeleteUsernameLinkOut,
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/DeleteUsernameLink";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: DeleteUsernameLinkRequest {},
            response_grpc: DeleteUsernameLinkResponse {},
            response: (),
        }]
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use futures_util::FutureExt as _;
    use libsignal_net::chat::fake::BodyWithTrailers;
    use libsignal_net_grpc::proto::chat::common::{IdentityType, ServiceIdentifier};
    use libsignal_net_grpc::proto::chat::services;
    use rand::RngCore as _;
    use test_case::test_case;
    use uuid::Uuid;

    use super::test_cases::ACI_UUID;
    use super::*;
    use crate::api::DisconnectedError;
    use crate::api::testutil::fixed_seed_test_rng;
    use crate::api::usernames::UnauthenticatedChatApi;
    use crate::grpc::testutil::{
        GrpcOverrideRequestValidator, RequestValidator, err, ok, req, run_tests,
        run_tests_with_generic_responses,
    };

    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: IdentityType::Aci.into(),
            uuid: ACI_UUID.as_bytes().to_vec(),
        })),
    }) => matches Ok(Some(aci)) if Uuid::from(aci) == ACI_UUID)]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: IdentityType::Pni.into(),
            uuid: ACI_UUID.as_bytes().to_vec(),
        })),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: 50,
            uuid: ACI_UUID.as_bytes().to_vec(),
        })),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: IdentityType::Aci.into(),
            uuid: vec![1, 2, 3],
        })),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::NotFound(Default::default())),
    }) => matches Ok(None))]
    #[test_case(err(tonic::Code::Internal) => matches Err(RequestError::Disconnected(DisconnectedError::Transport { .. })))]
    fn test_hash_lookup(
        response: http::Response<BodyWithTrailers>,
    ) -> Result<Option<Aci>, RequestError<Infallible>> {
        // Not realistic, but not likely to show up by accident.
        let hash = &[0x00, 0xff, 0xff, 0xff];

        let validator = GrpcOverrideRequestValidator {
            message: services::AccountsAnonymous::LookupUsernameHash.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.account.AccountsAnonymous/LookupUsernameHash",
                    LookupUsernameHashRequest {
                        username_hash: hash.to_vec(),
                    },
                ),
                response,
            },
        };

        Unauth(&validator)
            .look_up_username_hash(hash)
            .now_or_never()
            .expect("sync")
    }

    #[test]
    fn test_link_lookup() {
        use test_cases::*;
        run_tests(
            look_up_username_link_test_cases(),
            |chat: Unauth<_>, LookUpUsernameLinkArgs { uuid, entropy }| async move {
                chat.look_up_username_link(uuid, &entropy).await
            },
            |resp, result| match resp {
                LookUpUsernameLinkOut::Success(username) => {
                    assert_matches!(result, Ok(Some(x)) if x.to_string() == username)
                }
                LookUpUsernameLinkOut::NotFound => {
                    assert_matches!(result, Ok(None))
                }
                LookUpUsernameLinkOut::LinkDataTooShort => assert_matches!(
                    result,
                    Err(RequestError::Other(
                        usernames::UsernameLinkError::UsernameLinkDataTooShort
                    ))
                ),
                LookUpUsernameLinkOut::MissingResponse => {
                    assert_matches!(result, Err(RequestError::Unexpected { .. }))
                }
            },
        );
    }

    #[test]
    fn test_reserve_username_hash() {
        use test_cases::*;
        run_tests(
            reserve_username_hash_test_cases(),
            |chat: Auth<_>, ReserveUsernameHashArgs { usernames }| async move {
                chat.reserve_username_hash(&usernames).await
            },
            |resp, result| match resp {
                ReserveUsernameHashOut::Success(winner) => {
                    assert_matches!(result, Ok(x) if x == winner)
                }
                ReserveUsernameHashOut::UsernameNotAvailable => {
                    assert_matches!(result, Err(RequestError::Other(UsernameNotAvailable)))
                }
            },
        );
    }

    #[test]
    fn expected_test_proof_matches_fixed_seed_rng() {
        let mut randomness = [0; 32];
        fixed_seed_test_rng().fill_bytes(&mut randomness);
        let proof = usernames::Username::new(test_cases::TEST_USERNAME)
            .expect("valid username")
            .proof(&randomness)
            .expect("can generate proof");
        assert_eq!(
            proof,
            test_cases::EXPECTED_TEST_PROOF,
            "expected (hex) {}",
            hex::encode(&proof)
        );
    }

    #[test]
    fn test_confirm_username() {
        use test_cases::*;
        run_tests(
            confirm_username_test_cases(),
            |chat: Auth<_>,
             ConfirmUsernameArgs {
                 username,
                 username_ciphertext,
             }| async move {
                chat.confirm_username(
                    &usernames::Username::new(&username).expect("valid username"),
                    username_ciphertext,
                    &mut fixed_seed_test_rng(),
                )
                .await
            },
            |resp, result| match resp {
                ConfirmUsernameOut::Success(handle) => {
                    assert_matches!(result, Ok(x) if x == handle)
                }
                ConfirmUsernameOut::ReservationNotFound => {
                    assert_matches!(
                        result,
                        Err(RequestError::Other(
                            ConfirmUsernameError::ReservationNotFound
                        ))
                    )
                }
                ConfirmUsernameOut::UsernameNotAvailable => {
                    assert_matches!(
                        result,
                        Err(RequestError::Other(
                            ConfirmUsernameError::UsernameNotAvailable
                        ))
                    )
                }
            },
        );
    }

    #[test]
    fn test_confirm_username_invalid_responses() {
        use test_cases::TEST_USERNAME;
        let username = usernames::Username::new(TEST_USERNAME).expect("valid username");
        let method = test_cases::CONFIRM_USERNAME_HASH_METHOD;
        let request_grpc = || ConfirmUsernameHashRequest {
            username_hash: username.hash().to_vec(),
            zk_proof: test_cases::EXPECTED_TEST_PROOF.to_vec(),
            username_ciphertext: test_cases::TEST_USERNAME_CIPHERTEXT.to_vec(),
        };
        let case = |name: &str, response_grpc, response| crate::grpc::GrpcTestCase {
            name: name.to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: request_grpc(),
            response_grpc,
            response,
        };
        run_tests_with_generic_responses(
            [
                case(
                    "missing response",
                    ok(ConfirmUsernameHashResponse { response: None }),
                    false,
                ),
                case(
                    "link handle is not a uuid",
                    ok(ConfirmUsernameHashResponse {
                        response: Some(ConfirmUsernameResponse::ConfirmedUsernameHash(
                            ConfirmedUsernameHash {
                                username_link_handle: vec![1, 2, 3],
                            },
                        )),
                    }),
                    false,
                ),
                case("grpc error", err(tonic::Code::Internal), true),
            ],
            |chat: Auth<_>, ()| async move {
                chat.confirm_username(
                    &usernames::Username::new(TEST_USERNAME).expect("valid username"),
                    test_cases::TEST_USERNAME_CIPHERTEXT.to_vec(),
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
    fn test_set_username_link() {
        use test_cases::*;
        run_tests(
            set_username_link_test_cases(),
            |chat: Auth<_>,
             SetUsernameLinkArgs {
                 username_ciphertext,
                 keep_link_handle,
             }| async move {
                chat.set_username_link(&username_ciphertext, keep_link_handle)
                    .await
            },
            |resp, result| match resp {
                SetUsernameLinkOut::Success(out) => {
                    assert_matches!(result, Ok(x) if x == out)
                }
                SetUsernameLinkOut::UsernameNotSet => {
                    assert_matches!(result, Err(RequestError::Other(UsernameNotSet)))
                }
            },
        );
    }

    #[test]
    fn test_delete_username_hash() {
        use test_cases::*;
        run_tests(
            delete_username_hash_test_cases(),
            |chat: Auth<_>, ()| async move { chat.delete_username_hash().await },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_delete_username_link() {
        use test_cases::*;
        run_tests(
            delete_username_link_test_cases(),
            |chat: Auth<_>, ()| async move { chat.delete_username_link().await },
            |(), result| assert_matches!(result, Ok(())),
        );
    }
}
