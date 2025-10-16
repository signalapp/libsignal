//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native.js';
import { TokioAsyncContext, Environment, Net } from '../net.js';
import { BackupKey, BackupForwardSecrecyToken } from '../AccountKeys.js';
import { MessageBackupKey } from '../MessageBackup.js';
import type {
  IoError,
  RateLimitedError,
  SvrAttestationError,
  SvrDataMissingError,
  SvrInvalidDataError,
  SvrRestoreFailedError,
} from '../Errors.js';

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
   * Opaque value that must be persisted and provided to the next call to {@link SvrB#store}.
   *
   * See the {@link SvrB} documentation for lifecycle and persistence handling
   * for this value.
   */
  nextBackupSecretData: Uint8Array;
};

class StoreBackupResponseImpl implements StoreBackupResponse {
  _nativeHandle: Native.BackupStoreResponse;
  constructor(handle: Native.BackupStoreResponse) {
    this._nativeHandle = handle;
  }
  get forwardSecrecyToken(): BackupForwardSecrecyToken {
    const tokenBytes = Native.BackupStoreResponse_GetForwardSecrecyToken(this);
    return new BackupForwardSecrecyToken(tokenBytes);
  }

  get metadata(): Uint8Array {
    return Native.BackupStoreResponse_GetOpaqueMetadata(this);
  }

  get nextBackupSecretData(): Uint8Array {
    return Native.BackupStoreResponse_GetNextBackupSecretData(this);
  }
}

/**
 * The result of preparing a backup to be stored with forward secrecy guarantees.
 *
 * This context contains all the necessary components to encrypt and store a backup using a
 * key derived from both the user's Account Entropy Pool and the SVR-B-protected
 * Forward Secrecy Token.
 *
 * @see {@link BackupForwardSecrecyToken}
 */
export type RestoreBackupResponse = {
  /**
   * The forward secrecy token used to derive MessageBackupKey instances.
   *
   * This token provides forward secrecy guarantees by ensuring that compromise of the backup key
   * alone is insufficient to decrypt backups. Each backup is protected by a value stored on
   * the SVR-B server that must be retrieved during restoration.
   */
  forwardSecrecyToken: BackupForwardSecrecyToken;

  /**
   * Opaque value that must be persisted and provided to the next call to {@link SvrB#store}.
   *
   * See the {@link SvrB} documentation for lifecycle and persistence handling
   * for this value.
   */
  nextBackupSecretData: Uint8Array;
};

class RestoreBackupResponseImpl implements RestoreBackupResponse {
  _nativeHandle: Native.BackupRestoreResponse;
  constructor(handle: Native.BackupRestoreResponse) {
    this._nativeHandle = handle;
  }
  get forwardSecrecyToken(): BackupForwardSecrecyToken {
    const tokenBytes =
      Native.BackupRestoreResponse_GetForwardSecrecyToken(this);
    return new BackupForwardSecrecyToken(tokenBytes);
  }

  get nextBackupSecretData(): Uint8Array {
    return Native.BackupRestoreResponse_GetNextBackupSecretData(this);
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
 * 2. If this is a fresh install, call {@link SvrB#createNewBackupChain} and store the result
 *    locally. Otherwise, retrieve the secret data from the last **successful** backup operation
 *    (store or restore).
 * 3. Call {@link SvrB#store}
 * 4. Use the returned forward secrecy token to derive encryption keys
 * 5. Encrypt and upload the backup data to the user's remote, off-device storage location,
 *    including the returned {@link StoreBackupResponse#metadata}. The upload **must succeed**
 *    before proceeding or the previous backup might become unretrievable.
 * 6. Store the {@link StoreBackupResponse#nextBackupSecretData} locally, overwriting any
 *    previously-saved value.
 *
 * ## Secret handling
 *
 * When calling {@link SvrB#store}, the `previousSecretData` parameter must be from the last call to
 * {@link SvrB#store} or {@link SvrB#restore} that succeeded. This "chaining" is used to construct
 * each backup file so that it can be decrypted with either the *previous* token stored in SVR-B, or
 * the *next* one, which is important in case the overall backup upload is ever interrupted.
 *
 * The returned secret from a successful store or restore should be persisted until it is
 * overwritten by the value from a subsequent successful call. The caller should use
 * {@link SvrB#createNewBackupChain} only for the very first backup with a particular backup key.
 *
 * ## Restore Flow
 *
 * 1. Create a {@link Net} instance and get the {@link SvrB} service via {@link Net#svrB}
 * 2. Fetch the backup metadata from storage
 * 3. Call {@link SvrB#fetchForwardSecrecyTokenFromServer} to get the forward secrecy token
 * 4. Use the token to derive decryption keys
 * 5. Decrypt and restore the backup data
 * 6. Store the returned {@link RestoreBackupResponse#nextBackupSecretData} locally.
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
   * Generates backup "secret data" for a fresh install.
   *
   * Should not be used if any previous backups exist for this `backupKey`, whether uploaded or
   * restored by the local device. See {@link SvrB} for more information.
   */
  createNewBackupChain(backupKey: BackupKey): Uint8Array {
    return Native.SecureValueRecoveryForBackups_CreateNewBackupChain(
      this.environment,
      backupKey.serialize()
    );
  }

  /**
   * Prepares a backup for storage with forward secrecy guarantees.
   *
   * This makes a network call to the SVR-B server to store the forward secrecy token and returns a
   * {@link StoreBackupResponse}. See its fields' documentation and {@link SvrB} for how to continue
   * persisting the backup on success.
   *
   * @param backupKey The backup key derived from the Account Entropy Pool (AEP).
   * @param previousSecretData Optional secret data from the most recent previous backup.
   * **Critical**: This MUST be the secret data from the most recent of the following:
   * - the last {@link #store} call whose returned {@link StoreBackupResponse#metadata} was
   * successfully uploaded, and whose `nextBackupSecretData` was persisted.
   * - the last {@link #restore} call
   * - the already-persisted result from {@link #createNewBackupChain}, only if neither of the other
   * two are available.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @returns a {@link StoreBackupResponse} containing the forward secrecy token, metadata, and
   * secret data.
   * @throws {SvrInvalidDataError} if the previous secret data is malformed. There's no choice here
   * but to **start a new chain**.
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   * @throws {IoError} if the network operation fails (connection, service, or timeout errors).
   * These can be **automatically retried** (backoff recommended), but some may indicate a possible
   * bug in libsignal or in the enclave.
   * @throws {SvrAttestationError} if enclave attestation fails. This indicates a possible bug in
   * libsignal or in the enclave.
   */
  async store(
    backupKey: BackupKey,
    previousSecretData: Uint8Array,
    options?: { abortSignal?: AbortSignal }
  ): Promise<StoreBackupResponse> {
    const promise = Native.SecureValueRecoveryForBackups_StoreBackup(
      this.asyncContext,
      backupKey.serialize(),
      previousSecretData,
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
   * associated with a specific backup. The token is required to derive the message backup keys for
   * decryption.
   *
   * The typical restore flow:
   * 1. Fetch the backup metadata (stored in a header in the backup file)
   * 2. Call this function to retrieve the forward secrecy token from SVR-B
   * 3. Use the token to derive message backup keys
   * 4. Decrypt and restore the backup data
   * 5. Store the returned {@link RestoreBackupResponse#nextBackupSecretData} locally.
   *
   * @param backupKey The backup key derived from the Account Entropy Pool (AEP).
   * @param metadata The metadata that was stored in a header in the backup file during backup
   * creation.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @returns The forward secrecy token needed to derive keys for decrypting the backup.
   * @throws {SvrInvalidDataError} if the previous secret data is malformed. In this case the user's
   * data is **not recoverable**.
   * @throws {SvrRestoreFailedError} if restoration fails (with remaining tries count). This should
   * never happen but if it does the user's data is **not recoverable**.
   * @throws {SvrDataMissingError} if the backup data is not found on the server, indicating an
   * **incorrect backup key** (which may in turn imply the user's data is not recoverable).
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   * @throws {IoError} if the network operation fails (connection, service, or timeout errors).
   * These can be **automatically retried** (backoff recommended), but some may indicate a possible
   * bug in libsignal or in the enclave.
   * @throws {SvrAttestationError} if enclave attestation fails. This indicates a possible bug in
   * libsignal or in the enclave.
   */
  async restore(
    backupKey: BackupKey,
    metadata: Uint8Array,
    options?: { abortSignal?: AbortSignal }
  ): Promise<RestoreBackupResponse> {
    const promise =
      Native.SecureValueRecoveryForBackups_RestoreBackupFromServer(
        this.asyncContext,
        backupKey.serialize(),
        metadata,
        this.connectionManager,
        this.auth.username,
        this.auth.password
      );
    const response = await this.asyncContext.makeCancellable(
      options?.abortSignal,
      promise
    );
    return new RestoreBackupResponseImpl(response);
  }

  /**
   * Attempts to remove the info stored with SVR-B for this particular username/password pair.
   *
   * This is a best-effort operation; a successful return means the data has been removed from (or
   * never was present in) the current SVR-B enclaves, but may still be present in previous ones
   * that have yet to be decommissioned. Conversely, a thrown error may still have removed
   * information from previous enclaves.
   *
   * This should not typically be needed; rather than explicitly removing an entry, the client
   * should generally overwrite with a new {@link #store} instead.
   *
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   * @throws {IoError} if the network operation fails (connection, service, or timeout errors).
   * These can be **automatically retried** (backoff recommended), but some may indicate a possible
   * bug in libsignal or in the enclave.
   * @throws {SvrAttestationError} if enclave attestation fails. This indicates a possible bug in
   * libsignal or in the enclave.
   */
  async remove(options?: { abortSignal?: AbortSignal }): Promise<void> {
    const promise = Native.SecureValueRecoveryForBackups_RemoveBackup(
      this.asyncContext,
      this.connectionManager,
      this.auth.username,
      this.auth.password
    );
    await this.asyncContext.makeCancellable(options?.abortSignal, promise);
  }
}
