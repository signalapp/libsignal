//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { Aci, ServiceId } from '../../Address.js';
import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import type {
  ExpiringProfileKeyCredential,
  GroupSendFullToken,
  ProfileKeyCredentialRequestContext,
  ServerPublicParams,
} from '../../zkgroup/index.js';
import type {
  StandardNetworkError,
  RequestUnauthorizedError,
  ProfileNotFound,
  ProfileCantBeDecoded,
  InvalidAvatarUploadCredentialPresentation,
} from '../../Errors.js';
import type { S3UploadForm } from '../Chat.js';
import type { CdnUrl } from './CdnUrl.js';
import * as zkgroup from '../../zkgroup/index.js';
import type { Bytes } from '@signalapp/types';
import type { FetchedProfile, ProfileEtag } from './Profile';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthProfilesService {}
}

export type UnauthProfileAuthorization =
  | {
      accessKey: Bytes;
    }
  | GroupSendFullToken;

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
  /**
   * Delete the account’s avatar from the CDN.
   *
   * Clients must also call setProfile() to remove the avatar URL from the
   * profile data.
   *
   * @throws {StandardNetworkError}
   * @throws {InvalidAvatarUploadCredentialPresentation} if the presented
   * credential is invalid.
   */
  deleteAvatar: (
    request: {
      credential: zkgroup.AvatarUploadCredentialPresentation;
    },
    options?: RequestOptions
  ) => Promise<void>;
  /**
   * Returns a credential to upload a v2 avatar.
   *
   * After uploading the avatar, the client
   * must call setProfile() with the new avatar URL in the encrypted data.
   *
   * Because avatars are uploaded anonymously, they have an expiration equal to the
   * idle account expiration. Clients must periodically (recommended: every 90 days)
   * call extendAvatarTtl() to extend the TTL.
   *
   * NOTE: any existing avatar associated with this credential will be deleted immediately
   * Clients should not be uploading v2 avatars until after the v1->v2 avatar transition.
   *
   * Uploads will be limited to uploadLength bytes. It must be in the range [1, 10485760]
   * (10 MiB), else the server will reject the upload.
   *
   * @throws {StandardNetworkError}
   * @throws {InvalidAvatarUploadCredentialPresentation} if the presented
   * credential is invalid.
   */
  getAvatarUploadForm: (
    request: {
      credential: zkgroup.AvatarUploadCredentialPresentation;
      uploadLength: number;
    },
    options?: RequestOptions
  ) => Promise<S3UploadForm>;
  /**
   * Retrieves profile data.
   *
   * @returns null if the provided etag is up-to-date.
   * @throws {ProfileNotFound} if the profile (version) could not be found
   * @throws {ProfileCantBeDecoded} if the profile failed to decode (e.g. due to
   * encryption or validation errors)
   * @throws {RequestUnauthorizedError} if the authorization fails
   * @throws {StandardNetworkError}
   */
  getProfile: (
    request: {
      aci: Aci;
      profileKey: zkgroup.ProfileKey;
      auth: UnauthProfileAuthorization;
      etag: ProfileEtag | null;
    },
    options?: RequestOptions
  ) => Promise<FetchedProfile | null>;
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

UnauthenticatedChatConnection.prototype.deleteAvatar = async function (
  {
    credential,
  }: {
    credential: zkgroup.AvatarUploadCredentialPresentation;
  },
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.UnauthenticatedChatConnection_delete_avatar({
    asyncContext: this._asyncContext,
    abortSignal: options?.abortSignal,
    chat: this._chatService,
    credential,
  });
};

UnauthenticatedChatConnection.prototype.getAvatarUploadForm = async function (
  {
    credential,
    uploadLength,
  }: {
    credential: zkgroup.AvatarUploadCredentialPresentation;
    uploadLength: number;
  },
  options?: RequestOptions
): Promise<S3UploadForm> {
  return await NativeNice.UnauthenticatedChatConnection_get_avatar_upload_form({
    asyncContext: this._asyncContext,
    abortSignal: options?.abortSignal,
    chat: this._chatService,
    credential,
    uploadLength,
  });
};

UnauthenticatedChatConnection.prototype.getProfile = async function (
  { aci, profileKey, auth, etag },
  options?: RequestOptions
): Promise<FetchedProfile | null> {
  return await NativeNice.UnauthenticatedChatConnection_get_profile({
    asyncContext: this._asyncContext,
    abortSignal: options?.abortSignal,
    chat: this._chatService,
    aci,
    profileKey,
    auth:
      'accessKey' in auth ? { accessKey: auth.accessKey } : { groupSend: auth },
    etag,
  });
};
