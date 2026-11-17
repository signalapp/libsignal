//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { ServiceId } from '../../Address.js';
import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type {
  ExpiringProfileKeyCredential,
  ProfileKeyCredentialRequestContext,
  ServerPublicParams,
} from '../../zkgroup/index.js';
import type {
  StandardNetworkError,
  RequestUnauthorizedError,
  ProfileNotFound,
  InvalidAvatarUploadCredentialPresentation,
} from '../../Errors.js';
import type { CdnUrl } from './CdnUrl.js';
import * as zkgroup from '../../zkgroup/index.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthProfilesService {}
}

export interface UnauthProfilesService {
  /**
   * Does an account with the given ACI or PNI exist?
   *
   * Throws / completes with failure only if the request can't be completed.
   */
  accountExists: (
    request: {
      account: ServiceId;
    },
    options?: RequestOptions
  ) => Promise<boolean>;

  /**
   * Fetches a profile key credential using the given request context.
   *
   * @throws {RequestUnauthorizedError} if the profile key does not match the access key stored on
   * the server.
   * @throws {ProfileNotFound} if the account in question does not exist or does not have a profile
   * (possible if they have not finished setting up their account). Check {@link #accountExists} if
   * you need to distinguish between these possibilities.
   * @throws {StandardNetworkError}
   */
  getProfileKeyCredential: (
    request: {
      requestContext: ProfileKeyCredentialRequestContext;
      serverParams: ServerPublicParams;
    },
    options?: RequestOptions
  ) => Promise<ExpiringProfileKeyCredential>;
  /**
   * Extend the TTL of a v2 avatar
   *
   * The server doesn’t know which v2 avatars correspond to which Signal account. As a result,
   * v2 avatars expire after a time. To keep an account’s avatar from expiring, clients must
   * call extendAvatarTtl() on a regular basis (recommended: every 90 days).
   *
   * It is safe to keep calling this during the v1->v2 transition. v1 avatars will just be
   * treated as "not found."
   *
   * @returns either the CdnUrl of the current v2 avatar, or null, if none is set.
   * @throws {StandardNetworkError}
   * @throws {InvalidAvatarUploadCredentialPresentation} if the presented
   * credential is invalid.
   */
  extendAvatarTtl: (
    request: {
      credential: zkgroup.AvatarUploadCredentialPresentation;
    },
    options?: RequestOptions
  ) => Promise<CdnUrl | null>;
}

UnauthenticatedChatConnection.prototype.accountExists = async function (
  {
    account,
  }: {
    account: ServiceId;
  },
  options?: RequestOptions
): Promise<boolean> {
  return await NativeNice.UnauthenticatedChatConnection_account_exists({
    asyncContext: this._asyncContext,
    abortSignal: options?.abortSignal,
    chat: this._chatService,
    account,
  });
};

UnauthenticatedChatConnection.prototype.getProfileKeyCredential =
  async function (
    { requestContext, serverParams },
    options?: RequestOptions
  ): Promise<ExpiringProfileKeyCredential> {
    return await NativeNice.UnauthenticatedChatConnection_get_profile_key_credential(
      {
        asyncContext: this._asyncContext,
        abortSignal: options?.abortSignal,
        chat: this._chatService,
        profileKeyRequestContext: requestContext,
        serverParams,
      }
    );
  };

UnauthenticatedChatConnection.prototype.extendAvatarTtl = async function (
  {
    credential,
  }: {
    credential: zkgroup.AvatarUploadCredentialPresentation;
  },
  options?: RequestOptions
): Promise<CdnUrl | null> {
  return await NativeNice.UnauthenticatedChatConnection_extend_avatar_ttl({
    asyncContext: this._asyncContext,
    abortSignal: options?.abortSignal,
    chat: this._chatService,
    credential,
  });
};
