//
// Copyright 2021 Signal Messenger, LLC.
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

type Result<T> = std::result::Result<T, ZkGroupError>;

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
            #[bridge_fn]
            fn [<$typ _CheckValidContents>](_obj: Serialized<$typ>) {
                // Do nothing; if we successfully deserialized the value, it's valid.
            }
        }
    };
}

fixed_length_serializable!(AuthCredential);
fixed_length_serializable!(AuthCredentialPresentation);
fixed_length_serializable!(AuthCredentialResponse);
fixed_length_serializable!(GroupMasterKey);
fixed_length_serializable!(GroupPublicParams);
fixed_length_serializable!(GroupSecretParams);
fixed_length_serializable!(PniCredential);
fixed_length_serializable!(PniCredentialPresentation);
fixed_length_serializable!(PniCredentialRequestContext);
fixed_length_serializable!(PniCredentialResponse);
fixed_length_serializable!(ProfileKey);
fixed_length_serializable!(ProfileKeyCiphertext);
fixed_length_serializable!(ProfileKeyCommitment);
fixed_length_serializable!(ProfileKeyCredential);
fixed_length_serializable!(ProfileKeyCredentialPresentation);
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
) -> Result<Serialized<GroupSecretParams>> {
    Ok(GroupSecretParams::generate(*randomness).into())
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
) -> Result<Uuid> {
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
) -> Result<Serialized<ProfileKey>> {
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
) -> Result<Vec<u8>> {
    params.encrypt_blob_with_padding(*randomness, plaintext, padding_len)
}

#[bridge_fn_buffer]
fn GroupSecretParams_DecryptBlobWithPadding(
    params: Serialized<GroupSecretParams>,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    params.decrypt_blob_with_padding(ciphertext)
}

#[bridge_fn]
fn ServerSecretParams_GenerateDeterministic(
    randomness: &[u8; RANDOMNESS_LEN],
) -> Result<Serialized<ServerSecretParams>> {
    Ok(ServerSecretParams::generate(*randomness).into())
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
) -> Result<[u8; SIGNATURE_LEN]> {
    params.sign(*randomness, message)
}

#[bridge_fn]
fn ServerPublicParams_ReceiveAuthCredential(
    params: Serialized<ServerPublicParams>,
    uuid: Uuid,
    redemption_time: u32,
    response: Serialized<AuthCredentialResponse>,
) -> Result<Serialized<AuthCredential>> {
    Ok(params
        .receive_auth_credential(*uuid.as_bytes(), redemption_time, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateAuthCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    auth_credential: Serialized<AuthCredential>,
) -> Result<Serialized<AuthCredentialPresentation>> {
    Ok(server_public_params
        .create_auth_credential_presentation(
            *randomness,
            group_secret_params.into_inner(),
            auth_credential.into_inner(),
        )
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    uuid: Uuid,
    profile_key: Serialized<ProfileKey>,
) -> Result<Serialized<ProfileKeyCredentialRequestContext>> {
    Ok(server_public_params
        .create_profile_key_credential_request_context(
            *randomness,
            *uuid.as_bytes(),
            profile_key.into_inner(),
        )
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreatePniCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    aci: Uuid,
    pni: Uuid,
    profile_key: Serialized<ProfileKey>,
) -> Result<Serialized<PniCredentialRequestContext>> {
    Ok(server_public_params
        .create_pni_credential_request_context(
            *randomness,
            *aci.as_bytes(),
            *pni.as_bytes(),
            profile_key.into_inner(),
        )
        .into())
}

#[bridge_fn]
fn ServerPublicParams_ReceiveProfileKeyCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<ProfileKeyCredentialRequestContext>,
    response: Serialized<ProfileKeyCredentialResponse>,
) -> Result<Serialized<ProfileKeyCredential>> {
    Ok(server_public_params
        .receive_profile_key_credential(&request_context, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_ReceivePniCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<PniCredentialRequestContext>,
    response: Serialized<PniCredentialResponse>,
) -> Result<Serialized<PniCredential>> {
    Ok(server_public_params
        .receive_pni_credential(&request_context, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateProfileKeyCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<ProfileKeyCredential>,
) -> Result<Serialized<ProfileKeyCredentialPresentation>> {
    Ok(server_public_params
        .create_profile_key_credential_presentation(
            *randomness,
            group_secret_params.into_inner(),
            profile_key_credential.into_inner(),
        )
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreatePniCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<PniCredential>,
) -> Result<Serialized<PniCredentialPresentation>> {
    Ok(server_public_params
        .create_pni_credential_presentation(
            *randomness,
            group_secret_params.into_inner(),
            profile_key_credential.into_inner(),
        )
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_serial: &[u8; RECEIPT_SERIAL_LEN],
) -> Result<Serialized<ReceiptCredentialRequestContext>> {
    Ok(server_public_params
        .create_receipt_credential_request_context(*randomness, *receipt_serial)
        .into())
}

#[bridge_fn]
fn ServerPublicParams_ReceiveReceiptCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<ReceiptCredentialRequestContext>,
    response: Serialized<ReceiptCredentialResponse>,
) -> Result<Serialized<ReceiptCredential>> {
    Ok(server_public_params
        .receive_receipt_credential(&request_context, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_credential: Serialized<ReceiptCredential>,
) -> Result<Serialized<ReceiptCredentialPresentation>> {
    Ok(server_public_params
        .create_receipt_credential_presentation(*randomness, &receipt_credential)
        .into())
}

#[bridge_fn]
fn ServerSecretParams_IssueAuthCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    uuid: Uuid,
    redemption_time: u32,
) -> Result<Serialized<AuthCredentialResponse>> {
    Ok(server_secret_params
        .issue_auth_credential(*randomness, *uuid.as_bytes(), redemption_time)
        .into())
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyAuthCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation: Serialized<AuthCredentialPresentation>,
) -> Result<()> {
    server_secret_params
        .verify_auth_credential_presentation(group_public_params.into_inner(), &presentation)
}

#[bridge_fn]
fn ServerSecretParams_IssueProfileKeyCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ProfileKeyCredentialRequest>,
    uuid: Uuid,
    commitment: Serialized<ProfileKeyCommitment>,
) -> Result<Serialized<ProfileKeyCredentialResponse>> {
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
fn ServerSecretParams_IssuePniCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ProfileKeyCredentialRequest>,
    aci: Uuid,
    pni: Uuid,
    commitment: Serialized<ProfileKeyCommitment>,
) -> Result<Serialized<PniCredentialResponse>> {
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
    presentation: Serialized<ProfileKeyCredentialPresentation>,
) -> Result<()> {
    server_secret_params
        .verify_profile_key_credential_presentation(group_public_params.into_inner(), &presentation)
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyPniCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation: Serialized<PniCredentialPresentation>,
) -> Result<()> {
    server_secret_params
        .verify_pni_credential_presentation(group_public_params.into_inner(), &presentation)
}

#[bridge_fn]
fn ServerSecretParams_IssueReceiptCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ReceiptCredentialRequest>,
    receipt_expiration_time: u64,
    receipt_level: u64,
) -> Result<Serialized<ReceiptCredentialResponse>> {
    Ok(server_secret_params
        .issue_receipt_credential(
            *randomness,
            &request,
            receipt_expiration_time,
            receipt_level,
        )
        .into())
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyReceiptCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> Result<()> {
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
) -> Result<()> {
    server_public_params.verify_signature(message, *notary_signature)
}

// FIXME: bridge_get
#[bridge_fn]
fn AuthCredentialPresentation_GetUuidCiphertext(
    presentation: Serialized<AuthCredentialPresentation>,
) -> Serialized<UuidCiphertext> {
    presentation.get_uuid_ciphertext().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn AuthCredentialPresentation_GetRedemptionTime(
    presentation: Serialized<AuthCredentialPresentation>,
) -> u32 {
    presentation.get_redemption_time()
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
fn ProfileKeyCredentialPresentation_GetUuidCiphertext(
    presentation: Serialized<ProfileKeyCredentialPresentation>,
) -> Serialized<UuidCiphertext> {
    presentation.get_uuid_ciphertext().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(
    presentation: Serialized<ProfileKeyCredentialPresentation>,
) -> Serialized<ProfileKeyCiphertext> {
    presentation.get_profile_key_ciphertext().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn PniCredentialPresentation_GetAciCiphertext(
    presentation: Serialized<PniCredentialPresentation>,
) -> Serialized<UuidCiphertext> {
    presentation.get_aci_ciphertext().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn PniCredentialPresentation_GetPniCiphertext(
    presentation: Serialized<PniCredentialPresentation>,
) -> Serialized<UuidCiphertext> {
    presentation.get_pni_ciphertext().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn PniCredentialPresentation_GetProfileKeyCiphertext(
    presentation: Serialized<PniCredentialPresentation>,
) -> Serialized<ProfileKeyCiphertext> {
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
) -> u64 {
    receipt_credential.get_receipt_expiration_time()
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
) -> u64 {
    presentation.get_receipt_expiration_time()
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
