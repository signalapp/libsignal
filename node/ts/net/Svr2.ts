//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native.js';
import { TokioAsyncContext, Environment } from '../net.js';
import type {
  IoError,
  RateLimitedError,
  SvrAttestationError,
  SvrDataMissingError,
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
 * The result of an SVR2 restore call.
 */
export type Svr2RestoreResponse = {
  /** The data that was protected with the given pin. */
  data: Uint8Array<ArrayBuffer>;
  /** Number of remaining restore attempts before the data is wiped. */
  triesRemaining: number;
};

/**
 * Service for Secure Value Recovery v2 (SVR2) operations against the current
 * production enclave.
 *
 * SVR2 stores a small piece of `data` (16-48 bytes) protected by a 32-byte
 * `pin`. The data can later be retrieved by presenting the same `pin`. After
 * `maxTries` failed restore attempts the enclave wipes the data.
 *
 * ## Storage flow
 *
 * Backup is a two-phase protocol. The first phase (`BackupRequest`) writes
 * the data to the enclave; the second phase (`ExposeRequest`) makes it
 * restorable. The SVR2 spec forbids retrying a `BackupRequest` with the same
 * data, so the two phases are exposed as separate calls:
 *
 * 1. `const session = await svr2.startBackup(pin, data, maxTries)` - phase 1.
 *    If it throws, it is safe to retry as `BackupRequest` failed.
 * 2. `await svr2.finishBackup(session)` - phase 2. If this throws, retry it
 *    with the same `session`; do **not** call `startBackup` again.
 *
 * ## Restore flow
 *
 * `await svr2.restore(pin)` returns the stored data and remaining tries.
 *
 * ## Usage
 *
 * ```typescript
 * const net = new Net({ env: Environment.Production, userAgent: 'MyApp' });
 * const svr2 = net.svr2({ username: 'u', password: 'p' });
 * const session = await svr2.startBackup(pin, data, 5);
 * await svr2.finishBackup(session);
 * const { data: restored } = await svr2.restore(pin);
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
   * Phase 1 of an SVR2 backup. Attempts sending `BackupRequest` to the current
   * enclave, followed by the `ExposeRequest` reusing the same connection,
   * and returns a session that must be passed to {@link #finishBackup} to
   * complete the operation.
   *
   * @param pin 32-byte hashed pin protecting the stored data.
   * @param data Value to protect; between 16 and 48 bytes.
   * @param maxTries Number of failed restore attempts the enclave will tolerate
   * before wiping the data. In `[1, 255]`.
   * @param options Optional configuration.
   * @param options.abortSignal An AbortSignal that will cancel the request.
   * @throws {RateLimitedError} if the server is rate limiting this client.
   * @throws {IoError} on network errors.
   * @throws {SvrAttestationError} if enclave attestation fails.
   */
  async startBackup(
    pin: Uint8Array<ArrayBuffer>,
    data: Uint8Array<ArrayBuffer>,
    maxTries: number,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2BackupSession> {
    const promise = Native.Svr2_StartBackup(
      this.asyncContext,
      pin,
      data,
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
   */
  async restore(
    pin: Uint8Array<ArrayBuffer>,
    options?: { abortSignal?: AbortSignal }
  ): Promise<Svr2RestoreResponse> {
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

  /**
   * Removes any data stored for this username/password pair from the current
   * SVR2 enclave. No-op if nothing is stored.
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
}
