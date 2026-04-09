//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import {
  RequestOptions,
  UnauthenticatedChatConnection,
  type UploadForm,
} from '../Chat.js';
import * as Native from '../../Native.js';
import {
  type BackupAuthCredential,
  type GenericServerPublicParams,
} from '../../zkgroup/index.js';
import { type PrivateKey } from '../../EcKeys.js';
import {
  type UploadTooLarge,
  type RequestUnauthorizedError,
  type StandardNetworkError,
} from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthBackupsService {}
}

export type BackupAuth = {
  credential: BackupAuthCredential;
  serverKeys: GenericServerPublicParams;
  signingKey: PrivateKey;
};

export type Rng = {
  __deterministicRngSeedForTesting: number;
};

export interface UnauthBackupsService {
  /**
   * Get a messages backup upload form
   *
   * @param rng should be omitted in production
   * @throws {UploadTooLarge} if `uploadSize` is too large
   * @throws {RequestUnauthorizedError} if `auth` is invalid
   * @throws {StandardNetworkError}
   */
  getUploadForm: (
    request: {
      auth: BackupAuth;
      uploadSize: number;
      rng?: Rng;
    },
    options?: RequestOptions
  ) => Promise<UploadForm>;
  /**
   * Get a media backup upload form
   *
   * @param rng should be omitted in production
   * @throws {UploadTooLarge} if `uploadSize` is too large
   * @throws {RequestUnauthorizedError} if authorization fails
   * @throws {StandardNetworkError}
   */
  getMediaUploadForm: (
    request: {
      auth: BackupAuth;
      uploadSize: number;
      rng?: Rng;
    },
    options?: RequestOptions
  ) => Promise<UploadForm>;
}

UnauthenticatedChatConnection.prototype.getUploadForm = async function (
  {
    auth: { credential, serverKeys, signingKey },
    uploadSize,
    rng,
  }: {
    auth: BackupAuth;
    uploadSize: number;
    rng?: Rng;
  },
  options?: RequestOptions
) {
  const { cdn, key, headers, signedUploadUrl } =
    await this._asyncContext.makeCancellable(
      options?.abortSignal,
      Native.UnauthenticatedChatConnection_backup_get_upload_form(
        this._asyncContext,
        this._chatService,
        credential.getContents(),
        serverKeys.getContents(),
        signingKey,
        BigInt(uploadSize),
        rng?.__deterministicRngSeedForTesting ?? -1
      )
    );
  return {
    cdn,
    key,
    headers: new Map(headers),
    signedUploadUrl: new URL(signedUploadUrl),
  };
};

UnauthenticatedChatConnection.prototype.getMediaUploadForm = async function (
  {
    auth: { credential, serverKeys, signingKey },
    uploadSize,
    rng,
  }: {
    auth: BackupAuth;
    uploadSize: number;
    rng?: Rng;
  },
  options?: RequestOptions
) {
  const { cdn, key, headers, signedUploadUrl } =
    await this._asyncContext.makeCancellable(
      options?.abortSignal,
      Native.UnauthenticatedChatConnection_backup_get_media_upload_form(
        this._asyncContext,
        this._chatService,
        credential.getContents(),
        serverKeys.getContents(),
        signingKey,
        BigInt(uploadSize),
        rng?.__deterministicRngSeedForTesting ?? -1
      )
    );
  return {
    cdn,
    key,
    headers: new Map(headers),
    signedUploadUrl: new URL(signedUploadUrl),
  };
};
