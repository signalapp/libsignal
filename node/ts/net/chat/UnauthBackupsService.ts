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
import * as NativeNice from '../../NativeNice.js';
import {
  type BackupAuthCredential,
  type GenericServerPublicParams,
} from '../../zkgroup/index.js';
import { type CdnCredentials } from './CdnCredentials.js';
import { type PrivateKey } from '../../EcKeys.js';
import { type Rng } from '../../RngForTesting.js';
import {
  type UploadTooLarge,
  type RequestUnauthorizedError,
  type StandardNetworkError,
} from '../../Errors.js';

export { type CdnCredentials } from './CdnCredentials.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthBackupsService {}
}

export type BackupAuth = {
  credential: BackupAuthCredential;
  serverKeys: GenericServerPublicParams;
  signingKey: PrivateKey;
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

  /**
   * Sets the messages or media backup key based on `auth`.
   *
   * @param rng should be omitted in production
   * @throws {RequestUnauthorizedError} if authorization fails; since the key is being updated, this
   * suggests the credential in particular is invalid
   * @throws {StandardNetworkError}
   */
  setBackupPublicKey: (
    request: { auth: BackupAuth; rng?: Rng },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Fetches the credentials necessary to read from the given backup CDN.
   *
   * @param rng should be omitted in production
   * @throws {RequestUnauthorizedError} if authorization fails
   * @throws {StandardNetworkError}
   */
  getBackupCdnCredentials: (
    request: { auth: BackupAuth; cdn: number; rng?: Rng },
    options?: RequestOptions
  ) => Promise<CdnCredentials>;

  /**
   * Fetches the credentials for connecting to SVR-B (a username/password pair).
   *
   * @param rng should be omitted in production
   * @throws {RequestUnauthorizedError} if authorization fails
   * @throws {StandardNetworkError}
   */
  getBackupSvrBCredentials: (
    request: { auth: BackupAuth; rng?: Rng },
    options?: RequestOptions
  ) => Promise<{ username: string; password: string }>;

  /**
   * Indicates that the backup is still active.
   *
   * Clients must periodically upload new backups or perform a refresh. If a backup has not been
   * active for 30 days, it may be deleted.
   *
   * @param rng should be omitted in production
   * @throws {RequestUnauthorizedError} if authorization fails
   * @throws {StandardNetworkError}
   */
  refreshBackup: (
    request: { auth: BackupAuth; rng?: Rng },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Deletes all backup metadata, objects, and stored public key.
   *
   * To use backups again, a public key must be resupplied.
   *
   * @param rng should be omitted in production
   * @throws {RequestUnauthorizedError} if authorization fails
   * @throws {StandardNetworkError}
   */
  backupDeleteAll: (
    request: { auth: BackupAuth; rng?: Rng },
    options?: RequestOptions
  ) => Promise<void>;
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

UnauthenticatedChatConnection.prototype.setBackupPublicKey = async function (
  { auth: { credential, serverKeys, signingKey }, rng },
  options
) {
  await NativeNice.UnauthenticatedChatConnection_backup_set_public_key({
    asyncContext: this._asyncContext,
    chat: this._chatService,
    credential,
    serverKeys,
    signingKey,
    rng,
    abortSignal: options?.abortSignal,
  });
};

UnauthenticatedChatConnection.prototype.getBackupCdnCredentials =
  async function (
    { auth: { credential, serverKeys, signingKey }, cdn, rng },
    options
  ) {
    return await NativeNice.UnauthenticatedChatConnection_backup_get_cdn_credentials(
      {
        asyncContext: this._asyncContext,
        chat: this._chatService,
        cdn,
        credential,
        serverKeys,
        signingKey,
        rng,
        abortSignal: options?.abortSignal,
      }
    );
  };

UnauthenticatedChatConnection.prototype.getBackupSvrBCredentials =
  async function (
    { auth: { credential, serverKeys, signingKey }, rng },
    options
  ) {
    const [username, password] =
      await NativeNice.UnauthenticatedChatConnection_backup_get_svrb_credentials(
        {
          asyncContext: this._asyncContext,
          chat: this._chatService,
          credential,
          serverKeys,
          signingKey,
          rng,
          abortSignal: options?.abortSignal,
        }
      );
    return { username, password };
  };

UnauthenticatedChatConnection.prototype.refreshBackup = async function (
  { auth: { credential, serverKeys, signingKey }, rng },
  options
) {
  await NativeNice.UnauthenticatedChatConnection_backup_refresh({
    asyncContext: this._asyncContext,
    chat: this._chatService,
    credential,
    serverKeys,
    signingKey,
    rng,
    abortSignal: options?.abortSignal,
  });
};

UnauthenticatedChatConnection.prototype.backupDeleteAll = async function (
  { auth: { credential, serverKeys, signingKey }, rng },
  options
) {
  await NativeNice.UnauthenticatedChatConnection_backup_delete_all({
    asyncContext: this._asyncContext,
    chat: this._chatService,
    credential,
    serverKeys,
    signingKey,
    rng,
    abortSignal: options?.abortSignal,
  });
};
