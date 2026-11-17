//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type {
  StandardNetworkError,
  AccountMissingZkCredentialKey,
  SetProfileExpectedDataWriteConflict,
  SetProfilePaymentsForbiddenInRegion,
  SetProfileExpectedVersionWriteConflict,
  SetProfileInvalidProfile,
  ProfileCantBeDecoded,
  ProfileNotFound,
  IoError,
} from '../../Errors.js';
import { Aci } from '../../Address.js';
import type { S3UploadForm } from '../Chat.js';
import * as zkgroup from '../../zkgroup/index.js';
import type { Rng } from '../../RngForTesting.js';
import type {
  Profile,
  ProfileDataHash,
  ProfileEtag,
  FetchedProfile,
  AvatarCdnUrlValidationConfig,
} from './Profile.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthProfilesService {}
}

export interface AuthProfilesService {
  /**
   * Returns a form to upload a legacy (v1) avatar.
   *
   * @throws {StandardNetworkError}
   */
  getAvatarUploadFormLegacy: (
    request: {
      aci: Aci;
      profileKey: zkgroup.ProfileKey;
    },
    options?: RequestOptions
  ) => Promise<S3UploadForm>;
  /**
   * Returns an anonymous credential that may be presented with avatar operations in
   * UnauthProfilesService.
   *
   * @param aci the ACI of the current account
   * @param keyPair the ZkCredentialKeyPair of the current account
   * @param rotationId the ZkCredentialRotationId returned by the last call to
   * AuthAccountsService.setZkCredentialKey()
   * @param currentTimeSeconds defaults to the current time if not provided
   * @param rng should only be used for testing purposes
   *
   * @throws {AccountMissingZkCredentialKey} if the account doesn't have a
   * ZkCredentialKeyPair set (via AuthAccountsService.setZkCredentialKey())
   * @throws {StandardNetworkError}
   */
  getAvatarCredential: (
    request: {
      aci: Aci;
      keyPair: zkgroup.ZkCredentialKeyPair;
      rotationId: bigint;
      serverPublicParams: zkgroup.GenericServerPublicParams;
      currentTimeSeconds?: number;
      rng?: Rng;
    },
    options?: RequestOptions
  ) => Promise<zkgroup.AvatarUploadCredential>;
  /**
   * Set the profile for the current account.
   *
   * @param aci the ACI of the current account
   * @param profileKey the profile key to use when setting the profile. This can be the same, or
   * different from the current profile key.
   *
   * @param expectedCurrentProfileKeyVersion must be the current profile key version of the
   * account (or null if there is no current version). In case of mismatch, the resulting
   * error will contain the current profile key version, which may be passed into this parameter
   * on a subsequent request.
   *
   * @param expectedCurrentDataHash must exactly match the server’s view of the current profile v2
   * data hash. When changing to a new profile key, expectedCurrentDataHash must be null.
   * If this is the first v2 profile for this profile key, then expectedCurrentDataHash
   * must be null. Otherwise, expectedCurrentDataHash must be the result of the last
   * successful setProfile() invocation from across all devices on the account.
   *
   * Note that if an older client (not yet using libsignal to set profiles) sets a v1 profile,
   * this will clear out the v2 profile, and expectedCurrentDataHash should be null in
   * these cases.
   *
   * The easiest way to obtain the correct expectedCurrentDataHash is to invoke
   * getProfile() on the current account. The resulting FetchedProfile’s v2DataHash
   * will be the correct value (regardless of whether it’s null or not) to pass to the
   * expectedCurrentDataHash argument of this function.
   *
   * @returns The ProfileDataHash of the encrypted profile that was just uploaded.
   *
   * @throws {SetProfileInvalidProfile} if the provided profile isn't valid
   * @throws {SetProfileExpectedDataWriteConflict} if the current data hash
   * did not match the request's expectation, indicating  another device on the
   * account may have written an update the caller does not know about.
   * @throws {SetProfileExpectedVersionWriteConflict} if the current
   * version did not match the request's expectation, indicating another device
   * on the account may have created a new version the caller does not know
   * about.
   * @throws {SetProfilePaymentsForbiddenInRegion} if payments are not permitted in
   * the account's region, based on its phone number or the caller's IP address
   * if the account does not have a phone number. The request should be retried
   * without paymentAddress.
   * @throws {IoError} if profile.phoneNumberSharing is null
   * @throws {StandardNetworkError}
   */
  setProfile: (
    request: {
      aci: Aci;
      profileKey: zkgroup.ProfileKey;
      profile: Profile;
      expectedCurrentDataHash: ProfileDataHash | null;
      expectedCurrentProfileKeyVersion: zkgroup.ProfileKeyVersion | null;
      avatarCdnUrlValidationConfig: AvatarCdnUrlValidationConfig;
      rng?: Rng;
    },
    options?: RequestOptions
  ) => Promise<ProfileDataHash>;
  /**
   * Retrieves profile data.
   *
   * Callers with an unidentified access key for the account should use the
   * unauth version instead.
   *
   * @returns null if the provided etag is up-to-date.
   * @throws {ProfileNotFound} if the profile (version) could not be found
   * @throws {ProfileCantBeDecoded} if the profile failed to decode (e.g. due to
   * encryption or validation errors)
   * @throws {StandardNetworkError}
   */
  getProfile: (
    request: {
      aci: Aci;
      profileKey: zkgroup.ProfileKey;
      etag: ProfileEtag | null;
      avatarCdnUrlValidationConfig: AvatarCdnUrlValidationConfig;
    },
    options?: RequestOptions
  ) => Promise<FetchedProfile | null>;
}

AuthenticatedChatConnection.prototype.getAvatarUploadFormLegacy =
  async function (
    {
      aci,
      profileKey,
    }: {
      aci: Aci;
      profileKey: zkgroup.ProfileKey;
    },
    options?: RequestOptions
  ): Promise<S3UploadForm> {
    return await NativeNice.AuthenticatedChatConnection_get_avatar_upload_form_legacy(
      {
        asyncContext: this.asyncContext,
        abortSignal: options?.abortSignal,
        chat: this.chatService,
        aci,
        profileKey,
      }
    );
  };

AuthenticatedChatConnection.prototype.getAvatarCredential = async function (
  {
    aci,
    keyPair,
    rotationId,
    serverPublicParams,
    currentTimeSeconds,
    rng,
  }: {
    aci: Aci;
    keyPair: zkgroup.ZkCredentialKeyPair;
    rotationId: bigint;
    serverPublicParams: zkgroup.GenericServerPublicParams;
    currentTimeSeconds?: number;
    rng?: Rng;
  },
  options?: RequestOptions
): Promise<zkgroup.AvatarUploadCredential> {
  return await NativeNice.AuthenticatedChatConnection_get_avatar_credential({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    aci,
    keyPair,
    rotationId,
    serverPublicParams,
    currentTimeSeconds: BigInt(
      currentTimeSeconds ?? Math.floor(new Date().getTime() / 1000)
    ),
    rng,
  });
};

AuthenticatedChatConnection.prototype.setProfile = async function (
  {
    rng,
    aci,
    profileKey,
    profile,
    expectedCurrentDataHash,
    expectedCurrentProfileKeyVersion,
    avatarCdnUrlValidationConfig,
  },
  options?: RequestOptions
): Promise<ProfileDataHash> {
  return await NativeNice.AuthenticatedChatConnection_set_profile({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    rng,
    aci,
    profileKey,
    profile,
    expectedCurrentDataHash,
    expectedCurrentProfileKeyVersion,
    avatarCdnConfig: avatarCdnUrlValidationConfig,
  });
};

AuthenticatedChatConnection.prototype.getProfile = async function (
  { aci, profileKey, etag, avatarCdnUrlValidationConfig },
  options?: RequestOptions
): Promise<FetchedProfile | null> {
  return await NativeNice.AuthenticatedChatConnection_get_profile({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    aci,
    profileKey,
    etag,
    avatarCdnConfig: avatarCdnUrlValidationConfig,
  });
};
