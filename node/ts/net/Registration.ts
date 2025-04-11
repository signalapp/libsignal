//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';

import * as Native from '../../Native';
import { LibSignalError, RateLimitedError } from '../Errors';
import { newNativeHandle, type Net, type TokioAsyncContext } from '../net';
import { PublicKey } from '../EcKeys';
import { Aci, Pni, ServiceIdKind } from '../Address';
import { SignedKyberPublicPreKey, SignedPublicPreKey } from '..';

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

type CreateSessionArgs = Readonly<{
  e164: string;
}>;

type ResumeSessionArgs = Readonly<{
  sessionId: string;
  e164: string;
}>;

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
    { sessionId, e164 }: ResumeSessionArgs
  ): Promise<RegistrationService> {
    const session = await Native.RegistrationService_ResumeSession(
      options.tokioAsyncContext,
      sessionId,
      e164,
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
    { e164 }: CreateSessionArgs
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
    languages = [],
  }: {
    transport: 'sms' | 'voice';
    client: string;
    languages: string[];
  }): Promise<void> {
    await Native.RegistrationService_RequestVerificationCode(
      this.tokioAsyncContext,
      this,
      transport,
      client,
      languages
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

  public async registerAccount(inputs: {
    accountPassword: Uint8Array;
    skipDeviceTransfer: boolean;
    accountAttributes: AccountAttributes;
    aciPublicKey: PublicKey;
    pniPublicKey: PublicKey;
    aciSignedPreKey: SignedPublicPreKey;
    pniSignedPreKey: SignedPublicPreKey;
    aciPqLastResortPreKey: SignedKyberPublicPreKey;
    pniPqLastResortPreKey: SignedKyberPublicPreKey;
  }): Promise<RegisterAccountResponse> {
    const {
      accountPassword,
      skipDeviceTransfer = false,
      accountAttributes,
      aciPublicKey,
      pniPublicKey,
      aciSignedPreKey,
      pniSignedPreKey,
      aciPqLastResortPreKey,
      pniPqLastResortPreKey,
    } = inputs;
    const args = newNativeHandle(Native.RegisterAccountRequest_Create());
    Native.RegisterAccountRequest_SetAccountPassword(
      args,
      Buffer.from(accountPassword)
    );
    if (skipDeviceTransfer) {
      Native.RegisterAccountRequest_SetSkipDeviceTransfer(args);
    }
    Native.RegisterAccountRequest_SetIdentityPublicKey(
      args,
      ServiceIdKind.Aci,
      aciPublicKey
    );
    Native.RegisterAccountRequest_SetIdentityPublicKey(
      args,
      ServiceIdKind.Pni,
      pniPublicKey
    );

    Native.RegisterAccountRequest_SetIdentitySignedPreKey(
      args,
      ServiceIdKind.Aci,
      toBridgedPublicPreKey(aciSignedPreKey)
    );
    Native.RegisterAccountRequest_SetIdentitySignedPreKey(
      args,
      ServiceIdKind.Pni,
      toBridgedPublicPreKey(pniSignedPreKey)
    );
    Native.RegisterAccountRequest_SetIdentityPqLastResortPreKey(
      args,
      ServiceIdKind.Aci,
      toBridgedPublicPreKey(aciPqLastResortPreKey)
    );
    Native.RegisterAccountRequest_SetIdentityPqLastResortPreKey(
      args,
      ServiceIdKind.Pni,
      toBridgedPublicPreKey(pniPqLastResortPreKey)
    );

    return new RegisterAccountResponse(
      await Native.RegistrationService_RegisterAccount(
        this.tokioAsyncContext,
        this,
        args,
        accountAttributes
      )
    );
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

  /**
   * Create a registration client that sends requests to the returned fake chat.
   *
   * Calling code will need to retrieve the first fake remote from the fake chat
   * server and respond in order for the returned Promise to resolve.
   *
   * Internal, only public for testing
   */
  static fakeCreateSession(
    tokio: TokioAsyncContext,
    { e164 }: CreateSessionArgs
  ): [Promise<RegistrationService>, Native.Wrapper<Native.FakeChatServer>] {
    const server = newNativeHandle(Native.TESTING_FakeChatServer_Create());
    const registration = async () => {
      const handle = await Native.TESTING_FakeRegistrationSession_CreateSession(
        tokio,
        { number: e164 },
        server
      );
      return new RegistrationService(handle, tokio);
    };

    return [registration(), server];
  }
}

function toBridgedPublicPreKey(
  key: SignedPublicPreKey | SignedKyberPublicPreKey
): Native.SignedPublicPreKey {
  return {
    keyId: key.id(),
    signature: key.signature(),
    publicKey: key.publicKey().serialize(),
  };
}

export class AccountAttributes {
  readonly _nativeHandle: Native.RegistrationAccountAttributes;

  public constructor({
    recoveryPassword,
    aciRegistrationId,
    pniRegistrationId,
    registrationLock,
    unidentifiedAccessKey,
    unrestrictedUnidentifiedAccess,
    capabilities,
    discoverableByPhoneNumber,
  }: {
    recoveryPassword: Uint8Array;
    aciRegistrationId: number;
    pniRegistrationId: number;
    registrationLock: string | null;
    unidentifiedAccessKey: Uint8Array;
    unrestrictedUnidentifiedAccess: boolean;
    capabilities: Set<string>;
    discoverableByPhoneNumber: boolean;
  }) {
    const capabilitiesArray = Array.from(capabilities);

    this._nativeHandle = Native.RegistrationAccountAttributes_Create(
      Buffer.from(recoveryPassword),
      aciRegistrationId,
      pniRegistrationId,
      registrationLock,
      Buffer.from(unidentifiedAccessKey),
      unrestrictedUnidentifiedAccess,
      capabilitiesArray,
      discoverableByPhoneNumber
    );
  }
}

export class RegisterAccountResponse {
  public constructor(readonly _nativeHandle: Native.RegisterAccountResponse) {}

  public get aci(): Aci {
    return new Aci(
      Native.RegisterAccountResponse_GetIdentity(this, ServiceIdKind.Aci)
    );
  }

  public get pni(): Pni {
    return new Pni(
      Native.RegisterAccountResponse_GetIdentity(this, ServiceIdKind.Pni)
    );
  }

  public get number(): string {
    return Native.RegisterAccountResponse_GetNumber(this);
  }

  public get usernameHash(): Buffer | null {
    return Native.RegisterAccountResponse_GetUsernameHash(this);
  }
  public get usernameLinkHandle(): Buffer | null {
    return Native.RegisterAccountResponse_GetUsernameLinkHandle(this);
  }

  public get backupEntitlement(): {
    backupLevel: bigint;
    expirationSeconds: bigint;
  } | null {
    const backupLevel =
      Native.RegisterAccountResponse_GetEntitlementBackupLevel(this);
    const expirationSeconds =
      Native.RegisterAccountResponse_GetEntitlementBackupExpirationSeconds(
        this
      );
    if (backupLevel == null || expirationSeconds == null) return null;

    return {
      backupLevel,
      expirationSeconds,
    };
  }

  public get entitlementBadges(): Array<{
    id: string;
    expirationSeconds: number;
    visible: boolean;
  }> {
    return Native.RegisterAccountResponse_GetEntitlementBadges(this);
  }

  public get reregistration(): boolean {
    return Native.RegisterAccountResponse_GetReregistration(this);
  }
  public get storageCapable(): boolean {
    return Native.RegisterAccountResponse_GetStorageCapable(this);
  }
}
