//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type {
  StandardNetworkError,
  AccountMissingZkCredentialKey,
} from '../../Errors.js';
import { Aci } from '../../Address.js';
import type { S3UploadForm } from '../Chat.js';
import * as zkgroup from '../../zkgroup/index.js';
import type { Rng } from '../../RngForTesting.js';

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
