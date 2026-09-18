//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { EmptyObject } from 'type-fest';

import { RequestOptions, AuthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import { LibSignalErrorBase } from '../../Errors.js';
import type {
  GenericError,
  MfaNotVerified,
  StandardNetworkError,
  TooManyMfaKeys,
  TooManyTotpKeys,
  MfaKeyNotFound,
  WebAuthnRegistrationUnsuccessful,
} from '../../Errors.js';
import { SvrKey } from '../../AccountKeys.js';
import type { Rng } from '../../RngForTesting.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface AuthenticatedChatConnection extends AuthAccountsService {}
}

/**
 * The maximum length, in UTF-8 bytes, of an MFA key's name.
 */
export const MFA_KEY_NAME_MAX_LENGTH = 98;

function validateMfaMetadataCreatedAt(
  createdAt: number,
  operation:
    | 'confirmTotpKey'
    | 'setMfaKeyMetadata'
    | 'finishWebAuthnRegistration'
): void {
  if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
    throw new LibSignalErrorBase(
      'MFA key metadata createdAt must be a non-negative safe integer',
      'Generic',
      operation
    );
  }
}

/**
 * The user-specified metadata attached to a multi-factor authentication (MFA) key, such as a TOTP
 * key, on the account.
 *
 * This is stored encrypted on the server, so only the account's own devices can read it.
 */
export type MfaMetadata = {
  /**
   * A human-readable name for the key, at most {@link MFA_KEY_NAME_MAX_LENGTH} bytes when encoded
   * as UTF-8 and must not contain U+0000.
   */
  name: string;
  /**
   * When the key was created, in milliseconds since the epoch.
   *
   * Stored with one-second granularity, so a value read back from the server may be truncated
   * relative to the value that was written. Must be a non-negative safe integer.
   */
  createdAt: number;
};

/**
 * The parameters a TOTP generator needs, besides the key itself, to produce one-time passwords
 * the server will accept.
 */
export type TotpParameters = {
  /** The HMAC algorithm (e.g. "HmacSHA256") used by the TOTP generator. */
  algorithm: string;
  /**
   * The length of one-time passwords (in decimal digits) produced and expected by the TOTP
   * generator.
   */
  passwordLength: number;
  /** The time step (in seconds) used by the TOTP generator. */
  timeStepSeconds: number;
};

/**
 * A newly-generated TOTP key that is not yet active.
 *
 * Returned by {@link AuthAccountsService#generateTotpKey}; the key only starts being accepted for
 * the account once it is confirmed via {@link AuthAccountsService#confirmTotpKey}.
 */
export type PendingTotpKey = {
  /** The raw TOTP key. */
  key: Uint8Array<ArrayBuffer>;
  /** The TOTP parameters associated with the generated key. */
  parameters: TotpParameters;
};

/**
 * The parameters a WebAuthn authenticator needs to create a new credential for the account.
 *
 * Returned by {@link AuthAccountsService#startWebAuthnRegistration}; the caller passes these to
 * the platform's WebAuthn API to run a registration ceremony, then reports the outcome via
 * {@link AuthAccountsService#finishWebAuthnRegistration}.
 */
export type WebAuthnCreateParameters = {
  /** The "user handle" (`user.id`) that should be handed to the authenticator. */
  userHandle: Uint8Array<ArrayBuffer>;
  /**
   * The COSE IDs (https://www.iana.org/assignments/cose#algorithms) of acceptable algorithms for
   * the created key, as WebAuthn `COSEAlgorithmIdentifier`s.
   */
  allowedAlgorithms: Array<number>;
  /**
   * The credential IDs already registered for this account.
   *
   * These can be passed to candidate authenticators to tell them not to create a new key if they
   * already have a private key matching one of these.
   */
  excludeCredentialIds: Array<Uint8Array<ArrayBuffer>>;
};

/**
 * The kind of a confirmed MFA key.
 *
 * `unknown` is a kind of key this version of libsignal doesn't know about; see
 * {@link AuthAccountsService#listMfaKeys}.
 */
export type MfaKeyKind = 'totp' | 'webAuthn' | 'unknown';

/**
 * A confirmed multi-factor authentication (MFA) key on the account, as returned by
 * {@link AuthAccountsService#listMfaKeys}.
 */
export type ConfirmedMfaKey = {
  /** The account-specific identifier for this key. */
  id: number;
  /**
   * The user-specified name and creation time attached to this key, or `null` if it could not be
   * decrypted with the provided SVR key; see {@link AuthAccountsService#listMfaKeys}.
   */
  metadata: MfaMetadata | null;
  /** What kind of MFA key this is. */
  kind: MfaKeyKind;
};

/**
 * Information necessary to run an MFA verification, returned by
 * {@link AuthAccountsService#startMfaVerification}.
 *
 * Note that it is possible for no methods of verification to be available; this occurs when the
 * account has no MFA keys, or when all registered keys are of a type this version of libsignal
 * does not support.
 */
export type StartMfaVerificationResponse = {
  /**
   * If true, the account has one or more TOTP keys registered and can complete verification with
   * {@link MfaVerificationCredentialTotp}.
   */
  hasTotp: boolean;
  /**
   * If present, the account has one or more WebAuthn keys registered and can complete
   * verification with {@link MfaVerificationCredentialWebAuthn} using the parameters
   * provided.
   */
  webauthnParams?: WebAuthnAuthenticationParameters;
};

export type WebAuthnAuthenticationParameters = {
  challenge: Uint8Array<ArrayBuffer>;
  /** After this interval, verification may fail even if everything else is done correctly. */
  timeoutSeconds: number;
  allowedCredentialIds: Uint8Array<ArrayBuffer>[];
};

/** @see MfaVerificationCredential */
export type MfaVerificationCredentialTotp = { totpPassword: number };
/** @see MfaVerificationCredential */
export type MfaVerificationCredentialWebAuthn = { webauthnJson: string };
/**
 * A credential used to demonstrate ownership of an MFA method.
 *
 * @see AuthAccountsService#startMfaVerification
 * @see AuthAccountsService#finishMfaVerification
 */
export type MfaVerificationCredential =
  | MfaVerificationCredentialTotp
  | MfaVerificationCredentialWebAuthn;

export interface AuthAccountsService {
  /**
   * Deletes the authenticated account, purging all associated data in the process.
   *
   * Only the account's primary device may delete the account.
   *
   * Deleting the account also invalidates its connections, so the response can race the resulting
   * disconnect. If the connection is interrupted before a response arrives, the deletion may
   * nevertheless have taken effect; callers should not treat a transport error as proof the
   * account still exists.
   *
   * @throws {StandardNetworkError}
   */
  deleteAccount: (options?: RequestOptions) => Promise<void>;

  /**
   * Sets the registration lock for the authenticated account, given the account's SVR key (which
   * Signal clients historically call the "master key").
   *
   * libsignal derives the registration lock secret from the SVR key and sends only that secret;
   * the SVR key itself never leaves the device.
   *
   * While the registration lock is set, re-registering the account's phone number requires proving
   * knowledge of the secret.
   *
   * Only the account's primary device may set a registration lock.
   *
   * @param svrKey The account's SVR key, e.g. constructed from the bytes produced by
   * `AccountEntropyPool.deriveSvrKey`.
   *
   * @throws {StandardNetworkError}
   */
  setRegistrationLock: (
    request: {
      svrKey: SvrKey;
    },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Removes any registration lock from the authenticated account.
   *
   * This also succeeds if the account has no registration lock set, so a caller retrying a
   * removal sees the same result as the original call.
   *
   * Only the account's primary device may clear a registration lock.
   *
   * @throws {StandardNetworkError}
   */
  clearRegistrationLock: (options?: RequestOptions) => Promise<void>;

  /**
   * Sets the registration recovery password for the authenticated account, given the account's SVR
   * key (which Signal clients historically call the "master key").
   *
   * libsignal derives the registration recovery password from the SVR key and sends only that
   * derived password; the SVR key itself never leaves the device.
   *
   * The registration recovery password lets the account re-register its phone number without SMS
   * verification. Any of the account's devices may set it.
   *
   * @param svrKey The account's SVR key, e.g. constructed from the bytes produced by
   * `AccountEntropyPool.deriveSvrKey`.
   *
   * @throws {StandardNetworkError}
   */
  setRegistrationRecoveryPassword: (
    request: {
      svrKey: SvrKey;
    },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Sets whether the authenticated account may be discovered by phone number via the Contact
   * Discovery Service (CDS).
   *
   * If `false`, other users must discover this account by other means (e.g. by username).
   *
   * @throws {StandardNetworkError}
   */
  setDiscoverableByPhoneNumber: (
    request: {
      discoverable: boolean;
    },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Generates and stores a new pending TOTP key for the authenticated account.
   *
   * The key is generated by the server and returned along with the parameters a TOTP generator
   * needs to derive one-time passwords from it.
   *
   * The key does not become active until the client calls
   * {@link AuthAccountsService#confirmTotpKey} to prove it can generate one-time passwords using
   * the new key. The caller has 24 hours to confirm the key after it has been generated. This is
   * the only time the key material for this TOTP key is available; if it is lost, a new one will
   * need to be generated.
   *
   * @throws {TooManyTotpKeys} if the account already has too many TOTP keys; one must be removed
   * before adding more
   * @throws {TooManyMfaKeys} if the account already has too many MFA keys of all kinds; one must
   * be removed before adding more
   * @throws {StandardNetworkError}
   */
  generateTotpKey: (options?: RequestOptions) => Promise<PendingTotpKey>;

  /**
   * Confirms the account's pending TOTP key (see
   * {@link AuthAccountsService#generateTotpKey}), thus activating it.
   *
   * A TOTP key must be confirmed within 24 hours of its generation.
   *
   * `oneTimePassword` is a one-time password derived from the pending key. This should be
   * provided by the user from their TOTP app, proving they have stored the key and can correctly
   * generate passwords from it going forward.
   *
   * `metadata` (name, creation time) is attached to the newly-confirmed key and stored on the
   * server alongside the new key. It is stored encrypted, so that it may not be read by the
   * server.
   *
   * Resolves to the account-specific identifier assigned to the newly-confirmed key.
   *
   * A negative `oneTimePassword`, a metadata name longer than
   * {@link MFA_KEY_NAME_MAX_LENGTH} bytes of UTF-8 or containing U+0000, or a metadata creation
   * timestamp that is not a non-negative safe integer is a programmer error, reported as a
   * {@link GenericError}.
   *
   * @param rng should be omitted in production
   * @throws {MfaNotVerified} if the one-time password was not accepted for any reason
   * @throws {TooManyMfaKeys} if the account filled up with MFA keys between generating and
   * confirming this one
   * @throws {StandardNetworkError}
   */
  confirmTotpKey: (
    request: {
      oneTimePassword: number;
      metadata: MfaMetadata;
      svrKey: SvrKey;
      rng?: Rng;
    },
    options?: RequestOptions
  ) => Promise<number>;

  /**
   * Starts a WebAuthn registration ceremony, returning the parameters the authenticator needs to
   * create a new credential (passkey) for the authenticated account.
   *
   * The caller passes the returned {@link WebAuthnCreateParameters} to the platform's WebAuthn
   * API to run the ceremony, and then reports its outcome via
   * {@link AuthAccountsService#finishWebAuthnRegistration}. No MFA key is added until the ceremony
   * is finished, so a started registration that is never finished leaves the account's keys
   * unchanged.
   *
   * WebAuthn credentials may only be registered for accounts without phone numbers.
   *
   * @throws {TooManyMfaKeys} if the account already has too many MFA keys of all kinds, and one
   * must be removed before adding more
   * @throws {StandardNetworkError}
   */
  startWebAuthnRegistration: (
    options?: RequestOptions
  ) => Promise<WebAuthnCreateParameters>;

  /**
   * Concludes a WebAuthn registration ceremony (see
   * {@link AuthAccountsService#startWebAuthnRegistration}), adding the new credential (passkey) to
   * the authenticated account.
   *
   * `attestationObject` is the attestation object from the completed ceremony, serialized as
   * specified in https://www.w3.org/TR/webauthn/#attestation-object. `collectedClientDataJson` is
   * the "collected client data" map used in the ceremony, as the exact JSON map that was hashed
   * for the authenticator; it is passed through unchanged.
   *
   * A metadata name longer than {@link MFA_KEY_NAME_MAX_LENGTH} bytes of UTF-8 or containing
   * U+0000, or a metadata creation timestamp that is not a non-negative safe integer, is a
   * programmer error, reported as a {@link GenericError}.
   *
   * @param svrKey The account's SVR key to encrypt metadata with
   * @param rng should be omitted in production
   * @returns The account-specific identifier assigned to the newly-registered key
   * @throws {WebAuthnRegistrationUnsuccessful} if the ceremony's response was not verified
   * successfully, for any reason
   * @throws {TooManyMfaKeys} if the account filled up with MFA keys while the ceremony was running
   * @throws {StandardNetworkError}
   */
  finishWebAuthnRegistration: (
    request: {
      attestationObject: Uint8Array<ArrayBuffer>;
      collectedClientDataJson: string;
      metadata: MfaMetadata;
      svrKey: SvrKey;
      rng?: Rng;
    },
    options?: RequestOptions
  ) => Promise<number>;

  /**
   * Starts a verification check for any of the MFA keys on the authenticated account.
   *
   * WebAuthn verification is necessarily two-phase; this checks which MFA methods are available
   * and provides the necessary data to run a check for any of them.
   *
   * Note that it is possible for the returned {@link StartMfaVerificationResponse} to
   * not include any verification methods; this occurs when the account has no MFA keys,
   * or when all registered keys are of a type this version of libsignal does not support.
   *
   * If {@link StartMfaVerificationResponse#webauthnParams} are returned, the set of valid
   * {@link WebAuthnAuthenticationParameters#allowedCredentialIds} will be non-empty.
   *
   * @throws {StandardNetworkError}
   *
   * @see AuthAccountsService#finishMfaVerification
   */
  startMfaVerification: (
    request: EmptyObject,
    options?: RequestOptions
  ) => Promise<StartMfaVerificationResponse>;

  /**
   * Completes a verification check for any of the MFA keys on the authenticated account.
   *
   * WebAuthn verification is necessarily two-phase; this passes the response back to the chat
   * server to verify.
   *
   * @throws {MfaNotVerified} if the verification fails for any reason
   * @throws {StandardNetworkError}
   *
   * @see [startMfaVerification]
   */
  finishMfaVerification: (
    request: {
      credential: Readonly<MfaVerificationCredential>;
    },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Lists the confirmed MFA keys for the authenticated account.
   *
   * An item with a `null` {@link ConfirmedMfaKey#metadata} indicates that the metadata attached
   * to that key could not be decrypted with the provided {@link SvrKey} (e.g. because the SVR key
   * / AEP has rotated since the key was stored). If the user recalls the name for the key, this
   * state is recoverable by calling {@link AuthAccountsService#setMfaKeyMetadata}; otherwise, the
   * key with the unreadable name may be removed by calling
   * {@link AuthAccountsService#removeMfaKey}.
   *
   * Similarly, a key of a kind this version of libsignal doesn't recognize is still listed, with
   * an `unknown` {@link MfaKeyKind} (e.g. because it was added from a linked device running a
   * newer version of Signal).
   *
   * Pending (unconfirmed) keys are not included, and the key material itself is never returned.
   *
   * @throws {StandardNetworkError}
   */
  listMfaKeys: (
    request: {
      svrKey: SvrKey;
    },
    options?: RequestOptions
  ) => Promise<Array<ConfirmedMfaKey>>;

  /**
   * Replaces the metadata attached to the confirmed MFA key identified by `keyId`.
   *
   * A `keyId` outside the range of identifiers the server assigns, a metadata name longer than
   * {@link MFA_KEY_NAME_MAX_LENGTH} bytes of UTF-8 or containing U+0000, or a metadata creation
   * timestamp that is not a non-negative safe integer is a programmer error, reported as a
   * {@link GenericError}.
   *
   * @param rng should be omitted in production
   * @throws {MfaKeyNotFound} if no confirmed MFA key with the provided identifier was found on
   * the account
   * @throws {StandardNetworkError}
   */
  setMfaKeyMetadata: (
    request: {
      keyId: number;
      metadata: MfaMetadata;
      svrKey: SvrKey;
      rng?: Rng;
    },
    options?: RequestOptions
  ) => Promise<void>;

  /**
   * Removes the MFA key identified by `keyId` from the authenticated account.
   *
   * This is idempotent; removing a key ID that is not on the account also succeeds. A `keyId`
   * outside the range of identifiers the server assigns, however, is a programmer error, reported
   * as a {@link GenericError}.
   *
   * @throws {StandardNetworkError}
   */
  removeMfaKey: (
    request: {
      keyId: number;
    },
    options?: RequestOptions
  ) => Promise<void>;
}

AuthenticatedChatConnection.prototype.deleteAccount = async function (
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_delete_account({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

AuthenticatedChatConnection.prototype.setRegistrationLock = async function (
  {
    svrKey,
  }: {
    svrKey: SvrKey;
  },
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_set_registration_lock({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    svrKey: svrKey.getContents(),
  });
};

AuthenticatedChatConnection.prototype.clearRegistrationLock = async function (
  options?: RequestOptions
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_clear_registration_lock({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

AuthenticatedChatConnection.prototype.setRegistrationRecoveryPassword =
  async function (
    {
      svrKey,
    }: {
      svrKey: SvrKey;
    },
    options?: RequestOptions
  ): Promise<void> {
    return await NativeNice.AuthenticatedChatConnection_set_registration_recovery_password(
      {
        asyncContext: this.asyncContext,
        abortSignal: options?.abortSignal,
        chat: this.chatService,
        svrKey: svrKey.getContents(),
      }
    );
  };

AuthenticatedChatConnection.prototype.setDiscoverableByPhoneNumber =
  async function (
    {
      discoverable,
    }: {
      discoverable: boolean;
    },
    options?: RequestOptions
  ): Promise<void> {
    return await NativeNice.AuthenticatedChatConnection_set_discoverable_by_phone_number(
      {
        asyncContext: this.asyncContext,
        abortSignal: options?.abortSignal,
        chat: this.chatService,
        discoverable,
      }
    );
  };

AuthenticatedChatConnection.prototype.generateTotpKey = async function (
  options?
): Promise<PendingTotpKey> {
  return await NativeNice.AuthenticatedChatConnection_generate_totp_key({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
  });
};

AuthenticatedChatConnection.prototype.confirmTotpKey = async function (
  { oneTimePassword, metadata: { name, createdAt }, svrKey, rng },
  options?
): Promise<number> {
  validateMfaMetadataCreatedAt(createdAt, 'confirmTotpKey');
  return await NativeNice.AuthenticatedChatConnection_confirm_totp_key({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    oneTimePassword,
    name,
    createdAt,
    svrKey: svrKey.getContents(),
    rng,
  });
};

AuthenticatedChatConnection.prototype.startWebAuthnRegistration =
  async function (options?): Promise<WebAuthnCreateParameters> {
    return await NativeNice.AuthenticatedChatConnection_start_web_authn_registration(
      {
        asyncContext: this.asyncContext,
        abortSignal: options?.abortSignal,
        chat: this.chatService,
      }
    );
  };

AuthenticatedChatConnection.prototype.finishWebAuthnRegistration =
  async function (
    {
      attestationObject,
      collectedClientDataJson,
      metadata: { name, createdAt },
      svrKey,
      rng,
    },
    options?
  ): Promise<number> {
    validateMfaMetadataCreatedAt(createdAt, 'finishWebAuthnRegistration');
    return await NativeNice.AuthenticatedChatConnection_finish_web_authn_registration(
      {
        asyncContext: this.asyncContext,
        abortSignal: options?.abortSignal,
        chat: this.chatService,
        attestationObject,
        collectedClientDataJson,
        name,
        createdAt,
        svrKey: svrKey.getContents(),
        rng,
      }
    );
  };

AuthenticatedChatConnection.prototype.startMfaVerification = async function (
  _request,
  options?
): Promise<StartMfaVerificationResponse> {
  const { hasTotp, webauthnParams } =
    await NativeNice.AuthenticatedChatConnection_start_mfa_verification({
      asyncContext: this.asyncContext,
      abortSignal: options?.abortSignal,
      chat: this.chatService,
    });
  return { hasTotp, ...(webauthnParams !== null ? { webauthnParams } : {}) };
};

AuthenticatedChatConnection.prototype.finishMfaVerification = async function (
  { credential },
  options?
): Promise<void> {
  const bridgeCred: NativeNice.BridgeMfaVerificationCredential =
    'totpPassword' in credential
      ? { totp: credential.totpPassword }
      : { webAuthn: credential.webauthnJson };
  return NativeNice.AuthenticatedChatConnection_finish_mfa_verification({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    credential: bridgeCred,
  });
};

AuthenticatedChatConnection.prototype.listMfaKeys = async function (
  { svrKey },
  options?
): Promise<Array<ConfirmedMfaKey>> {
  const keys = await NativeNice.AuthenticatedChatConnection_list_mfa_keys({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    svrKey: svrKey.getContents(),
  });
  return keys.map(({ id, metadata, kind }) => ({
    id,
    metadata: metadata === 'unreadable' ? null : metadata.metadata,
    kind,
  }));
};

AuthenticatedChatConnection.prototype.setMfaKeyMetadata = async function (
  { keyId, metadata: { name, createdAt }, svrKey, rng },
  options?
): Promise<void> {
  validateMfaMetadataCreatedAt(createdAt, 'setMfaKeyMetadata');
  return await NativeNice.AuthenticatedChatConnection_set_mfa_key_metadata({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    keyId,
    name,
    createdAt,
    svrKey: svrKey.getContents(),
    rng,
  });
};

AuthenticatedChatConnection.prototype.removeMfaKey = async function (
  { keyId },
  options?
): Promise<void> {
  return await NativeNice.AuthenticatedChatConnection_remove_mfa_key({
    asyncContext: this.asyncContext,
    abortSignal: options?.abortSignal,
    chat: this.chatService,
    keyId,
  });
};
