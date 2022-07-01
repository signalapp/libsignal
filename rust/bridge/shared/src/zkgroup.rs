//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::zkgroup;
use zkgroup::auth::*;
use zkgroup::groups::*;
use zkgroup::profiles::*;
use zkgroup::receipts::*;
use zkgroup::*;

use libsignal_bridge_macros::*;
use std::convert::TryInto;
use uuid::Uuid;

use crate::support::*;
use crate::*;

/// Exposes a ZKGroup serializable type to the bridges via [`FixedLengthSerializable`].
///
/// `fixed_length_serializable!(FooBar)` generates
/// - `impl FixedLengthSerializable for FooBar`, using `[u8; FOO_BAR_LEN]` as the associated array
///   type.
/// - `#[bridge_fn] fn FooBar_CheckValidContents`, which checks that the type can be deserialized.
macro_rules! fixed_length_serializable {
    ($typ:ident) => {
        paste! {
            // Declare a marker type for TypeScript, the same as bridge_handle.
            // (This is harmless for the other bridges.)
            #[doc = "ts: interface " $typ " { readonly __type: unique symbol; }"]
            impl FixedLengthBincodeSerializable for $typ {
                type Array = [u8; [<$typ:snake:upper _LEN>]];
            }
            #[bridge_fn_void]
            fn [<$typ _CheckValidContents>](
                buffer: &[u8]
            ) -> Result<(), ZkGroupDeserializationFailure> {
                if buffer.len() != <$typ as FixedLengthBincodeSerializable>::Array::LEN {
                    return Err(ZkGroupDeserializationFailure)
                }
                match bincode::deserialize::<$typ>(buffer) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(ZkGroupDeserializationFailure)
                }
            }
        }
    };
}

fixed_length_serializable!(AuthCredential);
fixed_length_serializable!(AuthCredentialResponse);
fixed_length_serializable!(AuthCredentialWithPni);
fixed_length_serializable!(AuthCredentialWithPniResponse);
fixed_length_serializable!(ExpiringProfileKeyCredential);
fixed_length_serializable!(ExpiringProfileKeyCredentialResponse);
fixed_length_serializable!(GroupMasterKey);
fixed_length_serializable!(GroupPublicParams);
fixed_length_serializable!(GroupSecretParams);
fixed_length_serializable!(PniCredential);
fixed_length_serializable!(PniCredentialRequestContext);
fixed_length_serializable!(PniCredentialResponse);
fixed_length_serializable!(ProfileKey);
fixed_length_serializable!(ProfileKeyCiphertext);
fixed_length_serializable!(ProfileKeyCommitment);
fixed_length_serializable!(ProfileKeyCredential);
fixed_length_serializable!(ProfileKeyCredentialRequest);
fixed_length_serializable!(ProfileKeyCredentialRequestContext);
fixed_length_serializable!(ProfileKeyCredentialResponse);
fixed_length_serializable!(ReceiptCredential);
fixed_length_serializable!(ReceiptCredentialPresentation);
fixed_length_serializable!(ReceiptCredentialRequest);
fixed_length_serializable!(ReceiptCredentialRequestContext);
fixed_length_serializable!(ReceiptCredentialResponse);
fixed_length_serializable!(ServerPublicParams);
fixed_length_serializable!(ServerSecretParams);
fixed_length_serializable!(UuidCiphertext);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Timestamp(u64);

impl Timestamp {
    pub(crate) fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub(crate) fn as_seconds(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(seconds: u64) -> Self {
        Self::from_seconds(seconds)
    }
}

#[bridge_fn]
fn ProfileKey_GetCommitment(
    profile_key: Serialized<ProfileKey>,
    uuid: Uuid,
) -> Serialized<ProfileKeyCommitment> {
    profile_key.get_commitment(*uuid.as_bytes()).into()
}

#[bridge_fn]
fn ProfileKey_GetProfileKeyVersion(
    profile_key: Serialized<ProfileKey>,
    uuid: Uuid,
) -> [u8; PROFILE_KEY_VERSION_ENCODED_LEN] {
    let serialized = bincode::serialize(&profile_key.get_profile_key_version(*uuid.as_bytes()))
        .expect("can serialize");
    serialized.try_into().expect("right length")
}

#[bridge_fn]
fn GroupSecretParams_GenerateDeterministic(
    randomness: &[u8; RANDOMNESS_LEN],
) -> Serialized<GroupSecretParams> {
    GroupSecretParams::generate(*randomness).into()
}

#[bridge_fn]
fn GroupSecretParams_DeriveFromMasterKey(
    master_key: Serialized<GroupMasterKey>,
) -> Serialized<GroupSecretParams> {
    GroupSecretParams::derive_from_master_key(master_key.into_inner()).into()
}

// FIXME: Could be bridge_get! if we provide ArgTypeInfo for &GroupSecretParams.
#[bridge_fn]
fn GroupSecretParams_GetMasterKey(
    params: Serialized<GroupSecretParams>,
) -> Serialized<GroupMasterKey> {
    params.get_master_key().into()
}

// FIXME: Could be bridge_get! if we provide ArgTypeInfo for &GroupSecretParams.
#[bridge_fn]
fn GroupSecretParams_GetPublicParams(
    params: Serialized<GroupSecretParams>,
) -> Serialized<GroupPublicParams> {
    params.get_public_params().into()
}

#[bridge_fn]
fn GroupSecretParams_EncryptUuid(
    params: Serialized<GroupSecretParams>,
    uuid: Uuid,
) -> Serialized<UuidCiphertext> {
    params.encrypt_uuid(*uuid.as_bytes()).into()
}

#[bridge_fn]
fn GroupSecretParams_DecryptUuid(
    params: Serialized<GroupSecretParams>,
    uuid: Serialized<UuidCiphertext>,
) -> Result<Uuid, ZkGroupVerificationFailure> {
    Ok(Uuid::from_bytes(params.decrypt_uuid(uuid.into_inner())?))
}

#[bridge_fn]
fn GroupSecretParams_EncryptProfileKey(
    params: Serialized<GroupSecretParams>,
    profile_key: Serialized<ProfileKey>,
    uuid: Uuid,
) -> Serialized<ProfileKeyCiphertext> {
    params
        .encrypt_profile_key(profile_key.into_inner(), *uuid.as_bytes())
        .into()
}

#[bridge_fn]
fn GroupSecretParams_DecryptProfileKey(
    params: Serialized<GroupSecretParams>,
    profile_key: Serialized<ProfileKeyCiphertext>,
    uuid: Uuid,
) -> Result<Serialized<ProfileKey>, ZkGroupVerificationFailure> {
    Ok(params
        .decrypt_profile_key(profile_key.into_inner(), *uuid.as_bytes())?
        .into())
}

#[bridge_fn_buffer]
fn GroupSecretParams_EncryptBlobWithPaddingDeterministic(
    params: Serialized<GroupSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    plaintext: &[u8],
    padding_len: u32,
) -> Vec<u8> {
    params.encrypt_blob_with_padding(*randomness, plaintext, padding_len)
}

#[bridge_fn_buffer]
fn GroupSecretParams_DecryptBlobWithPadding(
    params: Serialized<GroupSecretParams>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    params.decrypt_blob_with_padding(ciphertext)
}

#[bridge_fn]
fn ServerSecretParams_GenerateDeterministic(
    randomness: &[u8; RANDOMNESS_LEN],
) -> Serialized<ServerSecretParams> {
    ServerSecretParams::generate(*randomness).into()
}

// FIXME: Could be bridge_get!
#[bridge_fn]
fn ServerSecretParams_GetPublicParams(
    params: Serialized<ServerSecretParams>,
) -> Serialized<ServerPublicParams> {
    params.get_public_params().into()
}

#[bridge_fn]
fn ServerSecretParams_SignDeterministic(
    params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    message: &[u8],
) -> [u8; SIGNATURE_LEN] {
    params.sign(*randomness, message)
}

#[bridge_fn]
fn ServerPublicParams_ReceiveAuthCredential(
    params: Serialized<ServerPublicParams>,
    uuid: Uuid,
    redemption_time: u32,
    response: Serialized<AuthCredentialResponse>,
) -> Result<Serialized<AuthCredential>, ZkGroupVerificationFailure> {
    Ok(params
        .receive_auth_credential(*uuid.as_bytes(), redemption_time, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_ReceiveAuthCredentialWithPni(
    params: Serialized<ServerPublicParams>,
    aci: Uuid,
    pni: Uuid,
    redemption_time: Timestamp,
    response: Serialized<AuthCredentialWithPniResponse>,
) -> Result<Serialized<AuthCredentialWithPni>, ZkGroupVerificationFailure> {
    Ok(params
        .receive_auth_credential_with_pni(
            *aci.as_bytes(),
            *pni.as_bytes(),
            redemption_time.as_seconds(),
            &response,
        )?
        .into())
}

#[bridge_fn_buffer]
fn ServerPublicParams_CreateAuthCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    auth_credential: Serialized<AuthCredential>,
) -> Vec<u8> {
    bincode::serialize(&server_public_params.create_auth_credential_presentation(
        *randomness,
        group_secret_params.into_inner(),
        auth_credential.into_inner(),
    ))
    .expect("can serialize")
}

#[bridge_fn_buffer]
fn ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    auth_credential: Serialized<AuthCredentialWithPni>,
) -> Vec<u8> {
    bincode::serialize(
        &server_public_params.create_auth_credential_with_pni_presentation(
            *randomness,
            group_secret_params.into_inner(),
            auth_credential.into_inner(),
        ),
    )
    .expect("can serialize")
}

#[bridge_fn]
fn ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    uuid: Uuid,
    profile_key: Serialized<ProfileKey>,
) -> Serialized<ProfileKeyCredentialRequestContext> {
    server_public_params
        .create_profile_key_credential_request_context(
            *randomness,
            *uuid.as_bytes(),
            profile_key.into_inner(),
        )
        .into()
}

#[bridge_fn]
#[allow(deprecated)]
fn ServerPublicParams_CreatePniCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    aci: Uuid,
    pni: Uuid,
    profile_key: Serialized<ProfileKey>,
) -> Serialized<PniCredentialRequestContext> {
    server_public_params
        .create_pni_credential_request_context(
            *randomness,
            *aci.as_bytes(),
            *pni.as_bytes(),
            profile_key.into_inner(),
        )
        .into()
}

#[bridge_fn]
fn ServerPublicParams_ReceiveProfileKeyCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<ProfileKeyCredentialRequestContext>,
    response: Serialized<ProfileKeyCredentialResponse>,
) -> Result<Serialized<ProfileKeyCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_profile_key_credential(&request_context, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_ReceiveExpiringProfileKeyCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<ProfileKeyCredentialRequestContext>,
    response: Serialized<ExpiringProfileKeyCredentialResponse>,
    current_time_in_seconds: Timestamp,
) -> Result<Serialized<ExpiringProfileKeyCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_expiring_profile_key_credential(
            &request_context,
            &response,
            current_time_in_seconds.as_seconds(),
        )?
        .into())
}

#[bridge_fn]
#[allow(deprecated)]
fn ServerPublicParams_ReceivePniCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<PniCredentialRequestContext>,
    response: Serialized<PniCredentialResponse>,
) -> Result<Serialized<PniCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_pni_credential(&request_context, &response)?
        .into())
}

#[bridge_fn_buffer]
fn ServerPublicParams_CreateProfileKeyCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<ProfileKeyCredential>,
) -> Vec<u8> {
    bincode::serialize(
        &server_public_params.create_profile_key_credential_presentation(
            *randomness,
            group_secret_params.into_inner(),
            profile_key_credential.into_inner(),
        ),
    )
    .expect("can serialize")
}

#[bridge_fn_buffer]
fn ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<ExpiringProfileKeyCredential>,
) -> Vec<u8> {
    bincode::serialize(
        &server_public_params.create_expiring_profile_key_credential_presentation(
            *randomness,
            group_secret_params.into_inner(),
            profile_key_credential.into_inner(),
        ),
    )
    .expect("can serialize")
}

#[bridge_fn_buffer]
#[allow(deprecated)]
fn ServerPublicParams_CreatePniCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    pni_credential: Serialized<PniCredential>,
) -> Vec<u8> {
    bincode::serialize(&server_public_params.create_pni_credential_presentation(
        *randomness,
        group_secret_params.into_inner(),
        pni_credential.into_inner(),
    ))
    .expect("can serialize")
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_serial: &[u8; RECEIPT_SERIAL_LEN],
) -> Serialized<ReceiptCredentialRequestContext> {
    server_public_params
        .create_receipt_credential_request_context(*randomness, *receipt_serial)
        .into()
}

#[bridge_fn]
fn ServerPublicParams_ReceiveReceiptCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<ReceiptCredentialRequestContext>,
    response: Serialized<ReceiptCredentialResponse>,
) -> Result<Serialized<ReceiptCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_receipt_credential(&request_context, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_credential: Serialized<ReceiptCredential>,
) -> Serialized<ReceiptCredentialPresentation> {
    server_public_params
        .create_receipt_credential_presentation(*randomness, &receipt_credential)
        .into()
}

#[bridge_fn]
fn ServerSecretParams_IssueAuthCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    uuid: Uuid,
    redemption_time: u32,
) -> Serialized<AuthCredentialResponse> {
    server_secret_params
        .issue_auth_credential(*randomness, *uuid.as_bytes(), redemption_time)
        .into()
}

#[bridge_fn]
fn ServerSecretParams_IssueAuthCredentialWithPniDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    aci: Uuid,
    pni: Uuid,
    redemption_time: Timestamp,
) -> Serialized<AuthCredentialWithPniResponse> {
    server_secret_params
        .issue_auth_credential_with_pni(
            *randomness,
            *aci.as_bytes(),
            *pni.as_bytes(),
            redemption_time.as_seconds(),
        )
        .into()
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyAuthCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: &[u8],
    current_time_in_seconds: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    server_secret_params.verify_auth_credential_presentation(
        group_public_params.into_inner(),
        &presentation,
        current_time_in_seconds.as_seconds(),
    )
}

#[bridge_fn]
fn ServerSecretParams_IssueProfileKeyCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ProfileKeyCredentialRequest>,
    uuid: Uuid,
    commitment: Serialized<ProfileKeyCommitment>,
) -> Result<Serialized<ProfileKeyCredentialResponse>, ZkGroupVerificationFailure> {
    Ok(server_secret_params
        .issue_profile_key_credential(
            *randomness,
            &request,
            *uuid.as_bytes(),
            commitment.into_inner(),
        )?
        .into())
}

#[bridge_fn]
fn ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ProfileKeyCredentialRequest>,
    uuid: Uuid,
    commitment: Serialized<ProfileKeyCommitment>,
    expiration_in_seconds: Timestamp,
) -> Result<Serialized<ExpiringProfileKeyCredentialResponse>, ZkGroupVerificationFailure> {
    Ok(server_secret_params
        .issue_expiring_profile_key_credential(
            *randomness,
            &request,
            *uuid.as_bytes(),
            commitment.into_inner(),
            expiration_in_seconds.as_seconds(),
        )?
        .into())
}

#[bridge_fn]
#[allow(deprecated)]
fn ServerSecretParams_IssuePniCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ProfileKeyCredentialRequest>,
    aci: Uuid,
    pni: Uuid,
    commitment: Serialized<ProfileKeyCommitment>,
) -> Result<Serialized<PniCredentialResponse>, ZkGroupVerificationFailure> {
    Ok(server_secret_params
        .issue_pni_credential(
            *randomness,
            &request,
            *aci.as_bytes(),
            *pni.as_bytes(),
            commitment.into_inner(),
        )?
        .into())
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyProfileKeyCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: &[u8],
    current_time_in_seconds: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    server_secret_params.verify_profile_key_credential_presentation(
        group_public_params.into_inner(),
        &presentation,
        current_time_in_seconds.as_seconds(),
    )
}

#[bridge_fn_void]
#[allow(deprecated)]
fn ServerSecretParams_VerifyPniCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = AnyPniCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    server_secret_params
        .verify_pni_credential_presentation(group_public_params.into_inner(), &presentation)
}

#[bridge_fn]
fn ServerSecretParams_IssueReceiptCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ReceiptCredentialRequest>,
    receipt_expiration_time: Timestamp,
    receipt_level: u64,
) -> Serialized<ReceiptCredentialResponse> {
    server_secret_params
        .issue_receipt_credential(
            *randomness,
            &request,
            receipt_expiration_time.as_seconds(),
            receipt_level,
        )
        .into()
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyReceiptCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> Result<(), ZkGroupVerificationFailure> {
    server_secret_params.verify_receipt_credential_presentation(&presentation)
}

// FIXME: Should be bridge_get!
#[bridge_fn]
fn GroupPublicParams_GetGroupIdentifier(
    group_public_params: Serialized<GroupPublicParams>,
) -> [u8; GROUP_IDENTIFIER_LEN] {
    group_public_params.get_group_identifier()
}

#[bridge_fn_void]
fn ServerPublicParams_VerifySignature(
    server_public_params: Serialized<ServerPublicParams>,
    message: &[u8],
    notary_signature: &[u8; SIGNATURE_LEN],
) -> Result<(), ZkGroupVerificationFailure> {
    server_public_params.verify_signature(message, *notary_signature)
}

#[bridge_fn_void]
fn AuthCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    AnyAuthCredentialPresentation::new(presentation_bytes)?;
    Ok(())
}

#[bridge_fn]
fn AuthCredentialPresentation_GetUuidCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_uuid_ciphertext().into()
}

#[bridge_fn_buffer]
fn AuthCredentialPresentation_GetPniCiphertext(presentation_bytes: &[u8]) -> Option<Vec<u8>> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation
        .get_pni_ciphertext()
        .map(|ciphertext| bincode::serialize(&ciphertext).expect("can serialize"))
}

#[bridge_fn]
fn AuthCredentialPresentation_GetRedemptionTime(presentation_bytes: &[u8]) -> Timestamp {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    Timestamp::from_seconds(presentation.get_redemption_time())
}

// FIXME: bridge_get
#[bridge_fn]
fn ProfileKeyCredentialRequestContext_GetRequest(
    context: Serialized<ProfileKeyCredentialRequestContext>,
) -> Serialized<ProfileKeyCredentialRequest> {
    context.get_request().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn PniCredentialRequestContext_GetRequest(
    context: Serialized<PniCredentialRequestContext>,
) -> Serialized<ProfileKeyCredentialRequest> {
    context.get_request().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ExpiringProfileKeyCredential_GetExpirationTime(
    credential: Serialized<ExpiringProfileKeyCredential>,
) -> Timestamp {
    credential.get_expiration_time().into()
}

#[bridge_fn_void]
fn ProfileKeyCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    AnyProfileKeyCredentialPresentation::new(presentation_bytes)?;
    Ok(())
}

#[bridge_fn]
fn ProfileKeyCredentialPresentation_GetUuidCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_uuid_ciphertext().into()
}

#[bridge_fn]
fn ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<ProfileKeyCiphertext> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_profile_key_ciphertext().into()
}

// Only used by the server.
#[bridge_fn_buffer(ffi = false, node = false)]
fn ProfileKeyCredentialPresentation_GetStructurallyValidV1PresentationBytes(
    presentation_bytes: &[u8],
) -> Vec<u8> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.to_structurally_valid_v1_presentation_bytes()
}

#[bridge_fn_void]
fn PniCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    AnyPniCredentialPresentation::new(presentation_bytes)?;
    Ok(())
}

#[bridge_fn]
fn PniCredentialPresentation_GetAciCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation = AnyPniCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_aci_ciphertext().into()
}

#[bridge_fn]
fn PniCredentialPresentation_GetPniCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation = AnyPniCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_pni_ciphertext().into()
}

#[bridge_fn]
fn PniCredentialPresentation_GetProfileKeyCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<ProfileKeyCiphertext> {
    let presentation = AnyPniCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_profile_key_ciphertext().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialRequestContext_GetRequest(
    request_context: Serialized<ReceiptCredentialRequestContext>,
) -> Serialized<ReceiptCredentialRequest> {
    request_context.get_request().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredential_GetReceiptExpirationTime(
    receipt_credential: Serialized<ReceiptCredential>,
) -> Timestamp {
    receipt_credential.get_receipt_expiration_time().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredential_GetReceiptLevel(receipt_credential: Serialized<ReceiptCredential>) -> u64 {
    receipt_credential.get_receipt_level()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialPresentation_GetReceiptExpirationTime(
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> Timestamp {
    presentation.get_receipt_expiration_time().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialPresentation_GetReceiptLevel(
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> u64 {
    presentation.get_receipt_level()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialPresentation_GetReceiptSerial(
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> [u8; RECEIPT_SERIAL_LEN] {
    presentation.get_receipt_serial_bytes()
}
