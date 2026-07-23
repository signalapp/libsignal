//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native.js';
import type { TokioAsyncContext, Environment } from '../net.js';
import type {
  IoError,
  RateLimitedError,
  SvrAttestationError,
  SvrDataMismatchError,
  SvrDataMissingError,
  SvrInvalidDataError,
  SvrRestoreFailedError,
} from '../Errors.js';

type ConnectionManager = Native.Wrapper<Native.ConnectionManager>;

/**
 * In-progress two-phase SVR2 backup.
 *
 * Returned by {@link Svr2#startBackup} once the server has acknowledged the
 * `BackupRequest`. Must be passed to {@link Svr2#finishBackup} to complete
 * the operation. If {@link Svr2#finishBackup} fails, the same session may be
 * retried; the `BackupRequest` itself is never re-sent.
 */
export class Svr2BackupSession {
  readonly _nativeHandle: Native.Svr2BackupSession;
  constructor(handle: Native.Svr2BackupSession) {
    this._nativeHandle = handle;
  }
}

/**
 * In-progress SVR2 enclave migration.
 *
 * Returned by {@link Svr2#migrate} and driven to completion by repeated calls to
 * it. The session can be serialized between calls so a long-running client job can
 * resume the migration across restarts.
 *
 * See {@link Svr2#migrate} for the drive-to-completion loop.
 */
export class Svr2MigrationSession {
  readonly _nativeHandle: Native.Svr2MigrationSession;
  constructor(handle: Native.Svr2MigrationSession) {
    this._nativeHandle = handle;
  }

  /**
   * Serializes the session so it can be persisted and later restored with
   * {@link #deserialize}.
   */
  serialize(): Uint8Array<ArrayBuffer> {
    return Native.Svr2MigrationSession_Serialize(this);
  }

  /**
   * Restores a session previously produced by {@link #serialize}.
   *
   * @throws {SvrInvalidDataError} if the bytes are corrupt or incompatible.
   */
  static deserialize(bytes: Uint8Array<ArrayBuffer>): Svr2MigrationSession {
    return new Svr2MigrationSession(
      Native.Svr2MigrationSession_Deserialize(bytes)
    );
  }

  /**
   * Whether the migration is finished. Once true, the most recent
   * migration is driven to completion.
   *
   * Keep the session and keep passing it to {@link Svr2#migrate} anyway: a
   * completed session is what lets `migrate` recognize there is nothing to do and
   * return with no network round trips, and it re-migrates automatically if the
   * current enclave has changed since.
   */
  isComplete(): boolean {
    return Native.Svr2MigrationSession_IsComplete(this);
  }
}

/**
 * The result of an SVR2 restore call.
 */
export type Svr2RestoreResponse = {
  /** The data that was protected with the given pin. */
  data: Uint8Array<ArrayBuffer>;
  /** Number of remaining restore attempts before the data is wiped. */
  triesRemaining: number;
};

/**
 * The result of restoring a master key with {@link Svr2#restore}.
 */
export type Svr2MasterKeyRestoreResponse = {
  /** The 32-byte master key that was protected with the given pin. */
  masterKey: Uint8Array<ArrayBuffer>;
  /** Number of remaining restore attempts before the data is wiped. */
  triesRemaining: number;
};

/**
 * Service for Secure Value Recovery v2 (SVR2) operations against the current
 * production enclave.
 *
 * SVR2 protects a 32-byte master key with a user's pin. The master key can later
 * be recovered by presenting the same pin. After `maxTries` failed restore
 * attempts the enclave wipes the stored data.
 *
 * ## Storage flow
 *
 * Backup is a two-phase protocol. The first phase (`BackupRequest`) writes
 * the data to the enclave, the second phase (`ExposeRequest`) makes it
 * restorable. The SVR2 spec forbids retrying a `BackupRequest` with the same
 * data, so the two phases are exposed as separate calls:
 *
 * 1. `const session = await svr2.startBackup({ normalizedPin }, masterKey, maxTries)`
 *    - phase 1. If it throws, it is safe to retry as `BackupRequest` failed.
 * 2. `await svr2.finishBackup(session)` - phase 2. If this throws, retry it
 *    with the same `session`; do **not** call `startBackup` again.
 *
 * ## Restore flow
 *
 * `await svr2.restore({ normalizedPin })` returns the master key and remaining
 * tries. It reads the current enclave first and falls back to the previous one
 * during an enclave rotation.
 *
 * ## Enclave migration
 *
 * SVR2 enclaves rotate periodically. {@link #migrate} writes a user's key to
 * the current enclave (leaving the previous one readable), and {@link #delete}
 * clears every configured enclave. Migration is full-service-only. See
 * {@link #migrate} for the drive-to-completion loop.
 *
 * ## Usage
 *
 * ```typescript
 * const net = new Net({ env: Environment.Production, userAgent: 'MyApp' });
 * const svr2 = net.svr2({ username: 'u', password: 'p' });
 * const session = await svr2.startBackup({ normalizedPin }, masterKey, 5);
 * await svr2.finishBackup(session);
 * const { masterKey: restored } = await svr2.restore({ normalizedPin });
 * ```
 */
export class Svr2 {
  constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly connectionManager: ConnectionManager,
    private readonly auth: Readonly<{ username: string; password: string }>,
    private readonly _environment: Environment
  ) {}

  /**
   * Hashes the pin and encrypts `masterKey` inside libsignal, then sends the
   * `BackupRequest` to the current enclave, followed by the `ExposeRequest`
   * reusing the same connection, and returns a session that must be passed to
   * {@link #finishBackup} to complete the operation.
   *
   * @param pin The user's pin, wrapped as `{ normalizedPin }` to make explicit
   * that the bytes must already be normalized and UTF-8 encoded. See the `Pin`
   * helper in `AccountKeys` for the normalization steps.
   * @param masterKey The 32-byte secret to protect with the pin.
   * @param maxTries Number of failed restore attempts the enclave will tolerate
   * before wiping the data. In `[1, 255]`.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   */
  startBackup(
    pin: { normalizedPin: Uint8Array<ArrayBuffer> },
    masterKey: Uint8Array<ArrayBuffer>,
    maxTries: number,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2BackupSession>;
  /**
   * Phase 1 of an SVR2 backup. Attempts sending `BackupRequest` to the current
   * enclave, followed by the `ExposeRequest` reusing the same connection,
   * and returns a session that must be passed to {@link #finishBackup} to
   * complete the operation.
   *
   * @param hashedPin 32-byte hashed pin protecting the stored data.
   * @param data Value to protect; between 16 and 48 bytes.
   * @param maxTries Number of failed restore attempts the enclave will tolerate
   * before wiping the data. In `[1, 255]`.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   * @deprecated Prefer the `{ normalizedPin }` overload, which hashes the pin and
   * encrypts the master key inside libsignal. This lower-level form requires the
   * caller to have already computed the 32-byte hashed pin and the encrypted
   * `data` blob.
   */
  startBackup(
    hashedPin: Uint8Array<ArrayBuffer>,
    data: Uint8Array<ArrayBuffer>,
    maxTries: number,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2BackupSession>;
  async startBackup(
    pin: Uint8Array<ArrayBuffer> | { normalizedPin: Uint8Array<ArrayBuffer> },
    dataOrMasterKey: Uint8Array<ArrayBuffer>,
    maxTries: number,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2BackupSession> {
    // A `Uint8Array` pin selects the deprecated raw-pin variant.
    const promise =
      pin instanceof Uint8Array
        ? Native.Svr2_StartBackup(
            this.asyncContext,
            pin,
            dataOrMasterKey,
            maxTries,
            this.connectionManager,
            this.auth.username,
            this.auth.password
          )
        : Native.Svr2_StartMasterKeyBackup(
            this.asyncContext,
            pin.normalizedPin,
            dataOrMasterKey,
            maxTries,
            this.connectionManager,
            this.auth.username,
            this.auth.password
          );
    const handle = await this.asyncContext.makeCancellable(
      options?.abortSignal,
      promise
    );
    return new Svr2BackupSession(handle);
  }

  /**
   * Phase 2 of an SVR2 backup. Sends an `ExposeRequest` for the session
   * returned by {@link #startBackup} if it did not complete in one go.
   *
   * Safe to retry with the same session if it throws. It is also safe to retry
   * if it succeeds, however it may result in a roundtrip to the server to
   * perform the idempotent `ExposeRequest` on each call.
   *
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   */
  async finishBackup(
    session: Svr2BackupSession,
    options?: { abortSignal?: AbortSignal }
  ): Promise<void> {
    const promise = Native.Svr2_FinishBackup(
      this.asyncContext,
      session,
      this.connectionManager,
      this.auth.username,
      this.auth.password
    );
    await this.asyncContext.makeCancellable(options?.abortSignal, promise);
  }

  /**
   * Retrieves and decrypts a master key stored with {@link #startBackup} +
   * {@link #finishBackup}. Hashes the pin inside libsignal, restores the stored
   * blob, and decrypts it back to the original 32-byte master key.
   *
   * If no data is found in the current enclave, it falls back to the previous
   * enclave if available.
   *
   * @param pin The user's pin, wrapped as `{ normalizedPin }` to make explicit
   * that the bytes must already be normalized and UTF-8 encoded. See the `Pin`
   * helper in `AccountKeys` for the normalization steps.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @throws {SvrDataMissingError} if no data is stored for this username/pin.
   * @throws {SvrRestoreFailedError} on pin mismatch (carries tries remaining).
   * @throws {SvrInvalidDataError} if the stored blob cannot be decrypted.
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   */
  restore(
    pin: { normalizedPin: Uint8Array<ArrayBuffer> },
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2MasterKeyRestoreResponse>;
  /**
   * Retrieves data previously stored with {@link #startBackup} +
   * {@link #finishBackup}.
   *
   * @param pin The 32-byte hashed pin originally used to store the data.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @throws {SvrDataMissingError} if no data is stored for this username/pin.
   * @throws {SvrRestoreFailedError} on pin mismatch (carries tries remaining).
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   * @deprecated Prefer the `{ normalizedPin }` overload, which hashes the pin and
   * decrypts the master key inside libsignal. This lower-level form returns the
   * raw encrypted blob that the caller must decrypt itself.
   */
  restore(
    pin: Uint8Array<ArrayBuffer>,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2RestoreResponse>;
  async restore(
    pin: Uint8Array<ArrayBuffer> | { normalizedPin: Uint8Array<ArrayBuffer> },
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2RestoreResponse | Svr2MasterKeyRestoreResponse> {
    // The deprecated variant
    if (pin instanceof Uint8Array) {
      const promise = Native.Svr2_Restore(
        this.asyncContext,
        pin,
        this.connectionManager,
        this.auth.username,
        this.auth.password
      );
      const [data, triesRemaining] = await this.asyncContext.makeCancellable(
        options?.abortSignal,
        promise
      );
      return { data, triesRemaining };
    }
    const promise = Native.Svr2_RestoreMasterKey(
      this.asyncContext,
      pin.normalizedPin,
      this.connectionManager,
      this.auth.username,
      this.auth.password
    );
    const [masterKey, triesRemaining] = await this.asyncContext.makeCancellable(
      options?.abortSignal,
      promise
    );
    return { masterKey, triesRemaining };
  }

  /**
   * Removes any data stored for this username/password pair from every configured
   * SVR2 enclave (the current one and, during an enclave rotation, the previous
   * one). No-op if nothing is stored.
   *
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   */
  async delete(options?: { abortSignal?: AbortSignal }): Promise<void> {
    const promise = Native.Svr2_Delete(
      this.asyncContext,
      this.connectionManager,
      this.auth.username,
      this.auth.password
    );
    await this.asyncContext.makeCancellable(options?.abortSignal, promise);
  }

  /**
   * Migrates this user's master key forward to the current SVR2 enclave, going
   * as far as it can in a single call.
   *
   * SVR2 enclaves rotate periodically. After a rotation a user's key may still
   * live only in the previous enclave. Migration writes the caller-provided
   * `masterKey` to the current enclave (unless it already holds it, so the
   * remaining-tries counter is preserved). It never touches the previous enclave,
   * which stays readable for clients that don't yet know the current one. This is
   * full-service-only (the `{ normalizedPin }` path); the pin hash salt is derived
   * per enclave, so the deprecated raw API cannot migrate.
   *
   * One method drives the whole migration: pass the session persisted from the
   * previous call (or omit it on the first), and it does the right thing without
   * you choosing a phase.
   *
   * - Already complete for the configured enclaves: returns it unchanged with no
   *   network round trips (and no crypto), so it is safe and cheap to call on
   *   every launch.
   * - Otherwise it makes progress and returns a session. In the happy path
   *   everything will be done in one call. If the final `ExposeRequest` did not
   *   succeed, the returned session is not yet complete. In this case call
   *   `migrate` again passing the returned session to retry the expose.
   *
   * ```typescript
   * // priorSession is the deserialized session from the last run, or undefined.
   * let session = await svr2.migrate(
   *   { normalizedPin }, masterKey, maxTries, priorSession);
   * persist(session.serialize());
   * while (!session.isComplete()) {
   *   session = await svr2.migrate({ normalizedPin }, masterKey, maxTries, session);
   *   persist(session.serialize());
   * }
   * ```
   *
   * @param pin The user's pin, wrapped as `{ normalizedPin }` to make explicit
   * that the bytes must already be normalized and UTF-8 encoded. See the `Pin`
   * helper in `AccountKeys` for the normalization steps.
   * @param pin.normalizedPin The normalized, UTF-8 encoded pin bytes.
   * @param masterKey The 32-byte master key to write forward. The caller already
   * holds it (from a prior {@link #restore} or its account keys).
   * @param maxTries Number of failed restore attempts the current enclave will
   * tolerate before wiping the migrated data. In `[1, 255]`.
   * @param priorSession The session persisted from a previous call. When it is
   * already complete for the currently configured enclaves the migration is
   * skipped with no network round trips. Omit on the first call.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   * @throws {SvrDataMismatchError} if the data is already present in the
   * current enclave but does not match the `masterKey`.
   */
  async migrate(
    pin: { normalizedPin: Uint8Array<ArrayBuffer> },
    masterKey: Uint8Array<ArrayBuffer>,
    maxTries: number,
    priorSession?: Svr2MigrationSession,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2MigrationSession> {
    const promise = Native.Svr2_Migrate(
      this.asyncContext,
      priorSession ?? null,
      pin.normalizedPin,
      masterKey,
      maxTries,
      this.connectionManager,
      this.auth.username,
      this.auth.password
    );
    const handle = await this.asyncContext.makeCancellable(
      options?.abortSignal,
      promise
    );
    return new Svr2MigrationSession(handle);
  }
}
