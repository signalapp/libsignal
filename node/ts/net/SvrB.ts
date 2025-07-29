//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../../Native';
import { TokioAsyncContext, Environment, Net } from '../net';
import { BackupKey, BackupForwardSecrecyToken } from '../AccountKeys';
import { MessageBackupKey } from '../MessageBackup';

type ConnectionManager = Native.Wrapper<Native.ConnectionManager>;

/**
 * The result of preparing a backup to be stored with forward secrecy guarantees.
 *
 * This context contains all the necessary components to encrypt and store a backup using a
 * key derived from both the user's Account Entropy Pool and the SVR-B-protected
 * Forward Secrecy Token.
 *
 * @see {@link BackupForwardSecrecyToken}
 */
export type StoreBackupResponse = {
  /**
   * The forward secrecy token used to derive MessageBackupKey instances.
   *
   * This token provides forward secrecy guarantees by ensuring that compromise of the backup key
   * alone is insufficient to decrypt backups. Each backup is protected by a value stored on
   * the SVR-B server that must be retrieved during restoration.
   */
  forwardSecrecyToken: BackupForwardSecrecyToken;

  /**
   * Opaque metadata that must be stored in the backup file.
   *
   * This metadata contains the encrypted forward secrecy token and other information required
   * to restore the backup. It must be retrievable when restoring the backup, as it's required
   * to fetch the forward secrecy token from SVR-B. This is currently stored in the header of
   * the backup file.
   */
  metadata: Uint8Array;

  /**
   * Opaque value that must be persisted and provided to the next call to {@link SvrB#storeBackup}.
   *
   * See the {@link SvrB} documentation for lifecycle and persistence handling
   * for this value.
   */
  nextBackupSecretData: Uint8Array;
};

class StoreBackupResponseImpl implements StoreBackupResponse {
  _nativeHandle: Native.BackupResponse;
  constructor(handle: Native.BackupResponse) {
    this._nativeHandle = handle;
  }
  get forwardSecrecyToken(): BackupForwardSecrecyToken {
    const tokenBytes = Native.BackupResponse_GetForwardSecrecyToken(this);
    return new BackupForwardSecrecyToken(tokenBytes);
  }

  get metadata(): Uint8Array {
    return Native.BackupResponse_GetOpaqueMetadata(this);
  }

  get nextBackupSecretData(): Uint8Array {
    return Native.BackupResponse_GetNextBackupSecretData(this);
  }
}

/**
 * Service for Secure Value Recovery for Backups (SVR-B) operations.
 *
 * This service provides forward secrecy for Signal backups using SVR-B. Forward secrecy ensures
 * that even if the user's Account Entropy Pool or Backup Key is compromised, the attacker can
 * decrypt a very small number of past backups. This is achieved by storing a token
 * in a secure enclave inside the SVR-B server, which provably attests that it
 * only stores a single token at a time for each user.
 *
 * ## Overview
 *
 * To achieve these properties, a secret token is required to derive the actual encryption
 * keys for the backup. At backup time, this token must be stored in the SVR-B server, overwriting the
 * previous token. At restore time, the token must be retrieved from the SVR-B server, and used to
 * derive the encryption keys for the backup.
 *
 * ## Storage Flow
 *
 * 1. Create a {@link Net} instance and get the {@link SvrB} service via {@link Net#svrB}
 * 2. Call {@link SvrB#storeBackup}
 *    - Pass the secret data from the last **successful** {@link SvrB#storeBackup} call
 *    - If no previous backup exists or the secret data is unavailable, pass `undefined`
 * 3. Use the returned forward secrecy token to derive encryption keys
 * 4. Encrypt and upload the backup data to the user's remote, off-device storage location, including the
 *    returned {@link StoreBackupResponse#metadata}. The upload **must succeed**
 *    before proceeding or the previous backup might become unretrievable.
 * 5. Store the {@link StoreBackupResponse#nextBackupSecretData} locally, overwriting any previously-saved value.
 *
 * ## Secret handling
 *
 * When calling {@link SvrB#storeBackup}, the `previousSecretData` parameter
 * must be from the last call to {@link SvrB#storeBackup} that
 * succeeded. The returned secret from a successful `storeBackup()` call should
 * be persisted until it is overwritten by the value from a subsequent
 * successful call. The caller should pass `undefined` as `previousSecretData`
 * only for the very first backup from a device.
 *
 * ## Restore Flow
 *
 * 1. Create a {@link Net} instance and get the {@link SvrB} service via {@link Net#svrB}
 * 2. Fetch the backup metadata from storage
 * 3. Call {@link SvrB#fetchForwardSecrecyTokenFromServer} to get the forward secrecy token
 * 4. Use the token to derive decryption keys
 * 5. Decrypt and restore the backup data
 *
 * ## Usage
 * ```typescript
 * const net = new Net({ env: Environment.Production, userAgent: 'MyApp' });
 * const auth = { username: 'myUsername', password: 'myPassword' };
 * const svrB = net.svrB(auth);
 *
 * // Prepare a backup
 * const stored = await svrB.storeBackup(myKey, previousSecretData);
 * // ... store backup with stored.forwardSecrecyToken remotely ...
 * // Securely persist stored.nextBackupSecretData for the next backup
 * ```
 *
 * @see {@link BackupKey}, {@link MessageBackupKey}, {@link BackupForwardSecrecyToken}
 */
export class SvrB {
  constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly connectionManager: ConnectionManager,
    private readonly auth: Readonly<{ username: string; password: string }>,
    private readonly environment: Environment
  ) {}

  /**
   * Prepares a backup for storage with forward secrecy guarantees.
   *
   * This makes a network call to the SVR-B server to store the forward secrecy token
   * and returns a {@link StoreBackupResponse}. See its fields' documentation and {@link SvrB}
   * for how to continue persisting the backup on success.
   *
   * @param backupKey The backup key derived from the Account Entropy Pool (AEP).
   * @param previousSecretData Optional secret data from the most recent previous backup.
   * **Critical**: This MUST be the {@link StoreBackupResponse#nextBackupSecretData} data
   * from the last {@link #storeBackup} whose returned {@link StoreBackupResponse#metadata} was
   * successfully uploaded, and whose `nextBackupSecretData` was persisted.
   * If `undefined`, starts a new chain and renders any prior backups unretrievable; this should
   * only be used for the very first backup from a device.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @returns a {@link StoreBackupResponse} containing the forward secrecy token, metadata, and secret data.
   * @throws Error if the previous secret data is malformed, or if  processing or upload fail.
   */
  async storeBackup(
    backupKey: BackupKey,
    previousSecretData?: Uint8Array,
    options?: { abortSignal?: AbortSignal }
  ): Promise<StoreBackupResponse> {
    const secretData = previousSecretData ?? new Uint8Array(0);
    const promise = Native.SecureValueRecoveryForBackups_StoreBackup(
      this.asyncContext,
      backupKey.serialize(),
      secretData,
      this.connectionManager,
      this.auth.username,
      this.auth.password
    );
    const response = await this.asyncContext.makeCancellable(
      options?.abortSignal,
      promise
    );
    return new StoreBackupResponseImpl(response);
  }

  /**
   * Fetches the forward secrecy token needed to decrypt a backup.
   *
   * This function makes a network call to the SVR-B server to retrieve the forward secrecy token
   * associated with a specific backup. The token is required to derive the message backup keys
   * for decryption.
   *
   * The typical restore flow:
   * 1. Fetch the backup metadata (stored in a header in the backup file)
   * 2. Call this function to retrieve the forward secrecy token from SVR-B
   * 3. Use the token to derive message backup keys
   * 4. Decrypt and restore the backup data
   *
   * @param backupKey The backup key derived from the Account Entropy Pool (AEP).
   * @param metadata The metadata that was stored in a header in the backup file during backup creation.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @returns The forward secrecy token needed to derive keys for decrypting the backup.
   * @throws Error if the metadata is invalid, the network operation fails, or the
   *   backup cannot be found.
   */
  async fetchForwardSecrecyTokenFromServer(
    backupKey: BackupKey,
    metadata: Uint8Array,
    options?: { abortSignal?: AbortSignal }
  ): Promise<BackupForwardSecrecyToken> {
    const promise =
      Native.SecureValueRecoveryForBackups_RestoreBackupFromServer(
        this.asyncContext,
        backupKey.serialize(),
        metadata,
        this.connectionManager,
        this.auth.username,
        this.auth.password
      );
    const tokenBytes = await this.asyncContext.makeCancellable(
      options?.abortSignal,
      promise
    );
    return new BackupForwardSecrecyToken(tokenBytes);
  }
}
