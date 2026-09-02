//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';

import * as Native from '../Native.js';
import {
  LibSignalError,
  RateLimitedError,
  RegistrationOneTimePasswordRequiredError,
  RegistrationRecoveryPasswordRequiredError,
  RegistrationRecoveryVerificationFailedError,
  RegisterAccountRequestRejectedError,
  RegistrationInvalidReceiptError,
} from '../Errors.js';
import type { Net, TokioAsyncContext } from '../net.js';
import { PublicKey } from '../EcKeys.js';
import { Aci, Pni, ServiceIdKind } from '../Address.js';
import {
  SignedKyberPublicPreKey,
  SignedPublicPreKey,
} from '../ProtocolTypes.js';
import { newNativeHandle } from '../internal.js';
import {
  convertNativeRegistrationSessionState,
  RegistrationSessionState,
} from './RegistrationSession.js';
import { FakeChatRemote } from './FakeChat.js';
import ReceiptCredentialPresentation from '../zkgroup/receipts/ReceiptCredentialPresentation.js';

export type { RegistrationSessionState };

type ConnectionManager = Native.Wrapper<Native.ConnectionManager>;

type RegistrationOptions = {
  tokioAsyncContext: TokioAsyncContext;
  connectionManager: ConnectionManager;
};

type CreateSessionArgs = Readonly<{
  e164: string;
}>;

type ResumeSessionArgs = Readonly<{
  sessionId: string;
  e164: string;
}>;

/** Inputs shared by every flow that registers or re-registers an account. */
export type CommonRegisterAccountArgs = {
  accountPassword: string;
  skipDeviceTransfer: boolean;
  accountAttributes: AccountAttributes;
  aciPublicKey: PublicKey;
  aciSignedPreKey: SignedPublicPreKey;
  aciPqLastResortPreKey: SignedKyberPublicPreKey;
};

/**
 * The PNI key material required by the flows that register a phone number.
 *
 * The server requires all of it to be present or all of it to be absent, so the
 * flows for an account with no phone number do not accept any of it.
 */
export type PniKeyArgs = {
  pniPublicKey: PublicKey;
  pniSignedPreKey: SignedPublicPreKey;
  pniPqLastResortPreKey: SignedKyberPublicPreKey;
};

/** Inputs to {@link RegistrationService.registerAccount}. */
export type RegisterAccountArgs = CommonRegisterAccountArgs & PniKeyArgs;

/** Inputs to {@link Net.reregisterAccount}. */
export type ReregisterAccountArgs = RegisterAccountArgs & { e164: string };

/** Inputs to {@link Net.registerAccountWithoutNumber}. */
export type RegisterAccountWithoutNumberArgs = CommonRegisterAccountArgs & {
  receiptCredentialPresentation: ReceiptCredentialPresentation;
};

/** Inputs to {@link Net.reregisterAccountWithoutNumber}. */
export type ReregisterAccountWithoutNumberArgs = CommonRegisterAccountArgs & {
  aci: Aci;
  oneTimePassword?: number;
};

export type Svr2CredentialResult = 'match' | 'no-match' | 'invalid';

/**
 * A client for the Signal registration service.
 *
 * This wraps a {@link Net} to provide a reliable registration service client.
 *
 * There are four ways to register, along two axes: whether the account has a
 * phone number, and whether it already exists. Only {@link
 * RegistrationService.registerAccount} needs a session, since proving control of
 * a phone number is an interactive process. The other three authenticate with
 * something the caller already holds and are called through {@link Net}:
 * {@link Net.reregisterAccount}, {@link Net.registerAccountWithoutNumber}, and
 * {@link Net.reregisterAccountWithoutNumber}.
 *
 * @example
 * ```ts
 * const service = await net.createRegistrationSession({ e164 });
 *
 * // sessionState.requestedInformation may name a push challenge, but these
 * // bindings expose no push-challenge API. Only submitCaptcha() is available;
 * // loop until sessionState.allowedToRequestCode is true.
 *
 * await service.requestVerification({ transport: 'sms', client, languages });
 * const verified = await service.verifySession(codeFromUser);
 *
 * const response = await service.registerAccount(args);
 * ```
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

  /**
   * Request that a verification code be sent via the given transport method.
   *
   * With the websocket transport, this makes a POST request to
   * `/v1/verification/session/{sessionId}/code`.
   *
   * The `languages` parameter should be a list of languages in Accept-Language syntax. Note that
   * "quality weighting" can be left out; the Signal server will always consider the list to be in
   * priority order.
   */
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

  public async checkSvr2Credentials(
    svr2Tokens: Array<string>
  ): Promise<Map<string, Svr2CredentialResult>> {
    return Native.RegistrationService_CheckSvr2Credentials(
      this.tokioAsyncContext,
      this,
      svr2Tokens
    );
  }

  /**
   * Registers an account that has a phone number.
   *
   * The session must already be verified.
   */
  public async registerAccount(
    inputs: Readonly<RegisterAccountArgs>
  ): Promise<RegisterAccountResponse> {
    const request = new RegisterAccountRequest(inputs);
    return new RegisterAccountResponse(
      await Native.RegistrationService_RegisterAccount(
        this.tokioAsyncContext,
        this,
        request,
        inputs.accountAttributes
      )
    );
  }

  /**
   * Re-registers an account that has a phone number.
   *
   * Clients should not use this method directly, but should instead call
   * {@link Net.reregisterAccount}.
   */
  public static async reregisterAccount(
    options: ReadonlyDeep<RegistrationOptions>,
    inputs: Readonly<ReregisterAccountArgs>
  ): Promise<RegisterAccountResponse> {
    const { tokioAsyncContext, connectionManager } = options;
    const request = new RegisterAccountRequest(inputs);
    return new RegisterAccountResponse(
      await Native.RegistrationService_ReregisterAccount(
        tokioAsyncContext,
        connectionManager,
        inputs.e164,
        request,
        inputs.accountAttributes
      )
    );
  }

  /**
   * Registers a new account that has no phone number.
   *
   * `accountAttributes.recoveryPassword` must not be empty: a recovery
   * password is the only way an account with no phone number can ever be
   * recovered.
   *
   * Clients should not use this method directly, but should instead call
   * {@link Net.registerAccountWithoutNumber}.
   *
   * @throws {RegistrationRecoveryPasswordRequiredError} if the recovery
   * password is empty.
   * @throws {RegisterAccountRequestRejectedError} if the server rejects the
   * request, including when the receipt credential presentation can't be
   * parsed.
   * @throws {RegistrationInvalidReceiptError} if the receipt credential
   * presentation fails verification, has expired, or has already been
   * redeemed.
   */
  public static async registerAccountWithoutNumber(
    options: ReadonlyDeep<RegistrationOptions>,
    inputs: Readonly<RegisterAccountWithoutNumberArgs>
  ): Promise<RegisterAccountResponse> {
    const { tokioAsyncContext, connectionManager } = options;
    const request = new RegisterAccountRequest(inputs);
    return new RegisterAccountResponse(
      await Native.RegistrationService_RegisterAccountWithoutNumber(
        tokioAsyncContext,
        connectionManager,
        inputs.receiptCredentialPresentation.contents,
        request,
        inputs.accountAttributes
      )
    );
  }

  /**
   * Re-registers an account that has no phone number, identified by its ACI.
   *
   * The counterpart to {@link RegistrationService.reregisterAccount} for an account with no phone
   * number. No PNI keys are accepted here; libsignal generates the PNI material
   * the server requires and then discards.
   *
   * `accountAttributes.recoveryPassword` must not be empty, since a recovery
   * password is the only way such an account can ever be re-registered.
   *
   * `oneTimePassword` is sent as a number, so `012345` becomes `12345`. Can be
   * omitted if no TOTP was set up for the account.
   *
   * Clients should not use this method directly, but should instead call
   * {@link Net.reregisterAccountWithoutNumber}.
   *
   * @throws {RegistrationRecoveryPasswordRequiredError} if the recovery
   * password is empty.
   * @throws {RegistrationOneTimePasswordRequiredError} if no valid one-time
   * password was given.
   * @throws {RegistrationRecoveryVerificationFailedError} if the recovery
   * password could not be verified.
   * @throws {RegisterAccountRequestRejectedError} if the server rejects the
   * request.
   */
  public static async reregisterAccountWithoutNumber(
    options: ReadonlyDeep<RegistrationOptions>,
    inputs: Readonly<ReregisterAccountWithoutNumberArgs>
  ): Promise<RegisterAccountResponse> {
    const { tokioAsyncContext, connectionManager } = options;
    const request = new RegisterAccountRequest(inputs);
    return new RegisterAccountResponse(
      await Native.RegistrationService_ReregisterAccountWithoutNumber(
        tokioAsyncContext,
        connectionManager,
        inputs.aci.getServiceIdFixedWidthBinary(),
        request,
        inputs.accountAttributes
      )
    );
  }

  /**
   *  Internal, only public for testing
   */
  public static _convertNativeSessionState(
    session: Native.Wrapper<Native.RegistrationSession>
  ): RegistrationSessionState {
    return convertNativeRegistrationSessionState(session);
  }

  /**
   * Create a registration client that sends requests to the returned fake chat.
   *
   * Calling code will need to await and use the returned fake chat remote
   * to respond in order for the returned Promise<RegistrationService> to resolve.
   *
   * Internal, only public for testing
   */
  static fakeCreateSession(
    tokio: TokioAsyncContext,
    { e164 }: CreateSessionArgs
  ): [Promise<RegistrationService>, Promise<FakeChatRemote>] {
    const server = newNativeHandle(Native.TESTING_FakeChatServer_Create());
    const registration = async () => {
      const handle = await Native.TESTING_FakeRegistrationSession_CreateSession(
        tokio,
        { number: e164 },
        server
      );
      return new RegistrationService(handle, tokio);
    };

    const remote = async () => {
      return new FakeChatRemote(
        tokio,
        await Native.TESTING_FakeChatServer_GetNextRemote(tokio, server)
      );
    };

    return [registration(), remote()];
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
    recoveryPassword: Uint8Array<ArrayBuffer>;
    aciRegistrationId: number;
    pniRegistrationId: number;
    registrationLock: string | null;
    unidentifiedAccessKey: Uint8Array<ArrayBuffer>;
    unrestrictedUnidentifiedAccess: boolean;
    capabilities: Set<string>;
    discoverableByPhoneNumber: boolean;
  }) {
    const capabilitiesArray = Array.from(capabilities);

    this._nativeHandle = Native.RegistrationAccountAttributes_Create(
      recoveryPassword,
      aciRegistrationId,
      pniRegistrationId,
      registrationLock,
      unidentifiedAccessKey,
      unrestrictedUnidentifiedAccess,
      capabilitiesArray,
      discoverableByPhoneNumber
    );
  }
}

export class RegisterAccountResponse {
  public constructor(readonly _nativeHandle: Native.RegisterAccountResponse) {}

  public get aci(): Aci {
    return Aci.fromUuidBytes(Native.RegisterAccountResponse_GetAci(this));
  }

  /** `null` for an account with no phone number. */
  public get pni(): Pni | null {
    const pni = Native.RegisterAccountResponse_GetPni(this);
    return pni == null ? null : Pni.fromUuidBytes(pni);
  }

  /** `null` for an account with no phone number. */
  public get number(): string | null {
    return Native.RegisterAccountResponse_GetNumber(this);
  }

  /** Set only for an account with no phone number. */
  public get authCredentialSalt(): Uint8Array<ArrayBuffer> | null {
    return Native.RegisterAccountResponse_GetAuthCredentialSalt(this);
  }

  public get usernameHash(): Uint8Array<ArrayBuffer> | null {
    return Native.RegisterAccountResponse_GetUsernameHash(this);
  }
  public get usernameLinkHandle(): Uint8Array<ArrayBuffer> | null {
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

class RegisterAccountRequest {
  _nativeHandle: Native.RegisterAccountRequest;

  public constructor(inputs: {
    accountPassword: string;
    skipDeviceTransfer: boolean;
    oneTimePassword?: number;
    aciPublicKey: PublicKey;
    pniPublicKey?: PublicKey;
    aciSignedPreKey: SignedPublicPreKey;
    pniSignedPreKey?: SignedPublicPreKey;
    aciPqLastResortPreKey: SignedKyberPublicPreKey;
    pniPqLastResortPreKey?: SignedKyberPublicPreKey;
  }) {
    const {
      accountPassword,
      skipDeviceTransfer,
      oneTimePassword,
      aciPublicKey,
      pniPublicKey,
      aciSignedPreKey,
      pniSignedPreKey,
      aciPqLastResortPreKey,
      pniPqLastResortPreKey,
    } = inputs;
    this._nativeHandle = Native.RegisterAccountRequest_Create();
    Native.RegisterAccountRequest_SetAccountPassword(this, accountPassword);
    if (skipDeviceTransfer) {
      Native.RegisterAccountRequest_SetSkipDeviceTransfer(this);
    }
    if (oneTimePassword !== undefined) {
      Native.RegisterAccountRequest_SetOneTimePassword(this, oneTimePassword);
    }
    Native.RegisterAccountRequest_SetIdentityPublicKey(
      this,
      ServiceIdKind.Aci,
      aciPublicKey
    );
    if (pniPublicKey !== undefined) {
      Native.RegisterAccountRequest_SetIdentityPublicKey(
        this,
        ServiceIdKind.Pni,
        pniPublicKey
      );
    }

    Native.RegisterAccountRequest_SetIdentitySignedPreKey(
      this,
      ServiceIdKind.Aci,
      toBridgedPublicPreKey(aciSignedPreKey)
    );
    if (pniSignedPreKey !== undefined) {
      Native.RegisterAccountRequest_SetIdentitySignedPreKey(
        this,
        ServiceIdKind.Pni,
        toBridgedPublicPreKey(pniSignedPreKey)
      );
    }
    Native.RegisterAccountRequest_SetIdentityPqLastResortPreKey(
      this,
      ServiceIdKind.Aci,
      toBridgedPublicPreKey(aciPqLastResortPreKey)
    );
    if (pniPqLastResortPreKey !== undefined) {
      Native.RegisterAccountRequest_SetIdentityPqLastResortPreKey(
        this,
        ServiceIdKind.Pni,
        toBridgedPublicPreKey(pniPqLastResortPreKey)
      );
    }
  }
}
