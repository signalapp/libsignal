//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';
import * as Native from '../../Native';
import { LibSignalError, RateLimitedError } from '../Errors';
import { newNativeHandle, type Net, type TokioAsyncContext } from '../net';

type ConnectionManager = Native.Wrapper<Native.ConnectionManager>;

type RegistrationOptions = {
  tokioAsyncContext: TokioAsyncContext;
  connectionManager: ConnectionManager;
  connectionTimeoutMillis?: number;
};

export type RegistrationSessionState = {
  allowedToRequestCode: boolean;
  verified: boolean;
  nextSmsSecs?: number;
  nextCallSecs?: number;
  nextVerificationAttemptSecs?: number;
  requestedInformation: Set<'pushChallenge' | 'captcha'>;
};

/**
 * A client for the Signal registration service.
 *
 * This wraps a {@link Net} to provide a reliable registration service client.
 */
export class RegistrationService {
  private constructor(
    readonly _nativeHandle: Native.RegistrationService,
    private readonly tokioAsyncContext: TokioAsyncContext
  ) {}

  /**
   * The stable identifier for the session.
   *
   * This can be persisted and used later for resuming a session that was
   * interrupted.
   */
  public get sessionId(): string {
    return Native.RegistrationService_SessionId(this);
  }

  /**
   * The last known state of the session.
   *
   * The state received from the server is stored internally and is exposed via
   * this property.
   */
  public get sessionState(): RegistrationSessionState {
    return RegistrationService._convertNativeSessionState(
      newNativeHandle(Native.RegistrationService_RegistrationSession(this))
    );
  }

  /**
   * Resumes a previously created registration session.
   *
   * Asynchronously connects to the registration session and verifies that the
   * session is still available. If so, returns an initialized
   * `RegistrationService`. Otherwise the returned `Promise` is resolved with an
   * error.
   *
   * Clients should not use this method directly, but should instead call
   * {@link Net.resumeRegistrationSession}.
   *
   * @returns a `Promise` that resolves to the `RegistrationService` if
   * resumption is successful, otherwise a {@link LibSignalError}.
   */
  public static async resumeSession(
    options: ReadonlyDeep<RegistrationOptions>,
    { sessionId }: { sessionId: string }
  ): Promise<RegistrationService> {
    const session = await Native.RegistrationService_ResumeSession(
      options.tokioAsyncContext,
      sessionId,
      options.connectionManager
    );
    return new RegistrationService(session, options.tokioAsyncContext);
  }

  /**
   * Starts a new registration session.
   *
   * Asynchronously connects to the registration session and requests a new session.
   * If successful, returns an initialized `RegistrationService`. Otherwise the
   * returned `Promise` is resolved with an error.
   *
   * Clients should not use this method directly, but should instead call
   * {@link Net.createRegistrationSession}.
   *
   * @returns a `Promise` that resolves to the `RegistrationService` if
   * creation is successful, otherwise a {@link RateLimitedError} or other
   * {@link LibSignalError}.
   */
  public static async createSession(
    options: ReadonlyDeep<RegistrationOptions>,
    { e164 }: { e164: string }
  ): Promise<RegistrationService> {
    const session = await Native.RegistrationService_CreateSession(
      options.tokioAsyncContext,
      { number: e164 },
      options.connectionManager
    );
    return new RegistrationService(session, options.tokioAsyncContext);
  }

  public async submitCaptcha(
    captcha: string
  ): Promise<{ allowedToRequestCode: boolean }> {
    await Native.RegistrationService_SubmitCaptcha(
      this.tokioAsyncContext,
      this,
      captcha
    );
    return this.sessionState;
  }

  public async requestVerification({
    transport,
    client,
  }: {
    transport: 'sms' | 'voice';
    client: string;
  }): Promise<void> {
    await Native.RegistrationService_RequestVerificationCode(
      this.tokioAsyncContext,
      this,
      transport,
      client
    );
  }

  public async verifySession(code: string): Promise<boolean> {
    await Native.RegistrationService_SubmitVerificationCode(
      this.tokioAsyncContext,
      this,
      code
    );
    return this.sessionState.verified;
  }

  /**
   *  Internal, only public for testing
   */
  public static _convertNativeSessionState(
    session: Native.Wrapper<Native.RegistrationSession>
  ): RegistrationSessionState {
    const nextCallSecs = Native.RegistrationSession_GetNextCallSeconds(session);
    const nextSmsSecs = Native.RegistrationSession_GetNextSmsSeconds(session);
    const nextVerificationAttemptSecs =
      Native.RegistrationSession_GetNextVerificationAttemptSeconds(session);

    return {
      allowedToRequestCode:
        Native.RegistrationSession_GetAllowedToRequestCode(session),
      verified: Native.RegistrationSession_GetVerified(session),
      nextCallSecs: nextCallSecs != null ? nextCallSecs : undefined,
      nextSmsSecs: nextSmsSecs != null ? nextSmsSecs : undefined,
      nextVerificationAttemptSecs:
        nextVerificationAttemptSecs != null
          ? nextVerificationAttemptSecs
          : undefined,
      requestedInformation: new Set(
        Native.RegistrationSession_GetRequestedInformation(session)
      ),
    };
  }
}
