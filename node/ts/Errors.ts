//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { ProtocolAddress, ServiceId } from './Address.js';
import * as Native from './Native.js';

export enum ErrorCode {
  Generic,

  DuplicatedMessage,
  SealedSenderSelfSend,
  UntrustedIdentity,
  InvalidRegistrationId,
  InvalidProtocolAddress,
  VerificationFailed,
  InvalidSession,
  InvalidSenderKeySession,

  NicknameCannotBeEmpty,
  CannotStartWithDigit,
  MissingSeparator,
  BadNicknameCharacter,
  NicknameTooShort,
  NicknameTooLong,
  DiscriminatorCannotBeEmpty,
  DiscriminatorCannotBeZero,
  DiscriminatorCannotBeSingleDigit,
  DiscriminatorCannotHaveLeadingZeros,
  BadDiscriminatorCharacter,
  DiscriminatorTooLarge,

  IoError,
  CdsiInvalidToken,
  InvalidUri,

  InvalidMediaInput,
  UnsupportedMediaInput,

  InputDataTooLong,
  InvalidEntropyDataLength,
  InvalidUsernameLinkEncryptedData,

  RateLimitedError,
  RateLimitChallengeError,

  SvrDataMissing,
  SvrRequestFailed,
  SvrRestoreFailed,
  SvrAttestationError,
  SvrInvalidData,

  ChatServiceInactive,
  AppExpired,
  DeviceDelinked,
  ConnectionInvalidated,
  ConnectedElsewhere,

  BackupValidation,

  Cancelled,

  KeyTransparencyError,
  KeyTransparencyVerificationFailed,

  IncrementalMacVerificationFailed,

  RequestUnauthorized,
  MismatchedDevices,
}

/** Called out as a separate type so it's not confused with a normal ServiceIdBinary. */
type ServiceIdFixedWidthBinary = Uint8Array;

/**
 * A failure sending to a recipient on account of not being up to date on their devices.
 *
 * An entry in {@link MismatchedDevicesError}. Each entry represents a recipient that has either
 * added, removed, or relinked some devices in their account (potentially including their primary
 * device), as represented by the {@link MismatchedDevicesEntry#missingDevices},
 * {@link MismatchedDevicesEntry#extraDevices}, and {@link MismatchedDevicesEntry#staleDevices}
 * arrays, respectively. Handling the exception involves removing the "extra" devices and
 * establishing new sessions for the "missing" and "stale" devices.
 */
export class MismatchedDevicesEntry {
  account: ServiceId;
  missingDevices: number[];
  extraDevices: number[];
  staleDevices: number[];

  constructor({
    account,
    missingDevices,
    extraDevices,
    staleDevices,
  }: {
    account: ServiceId | ServiceIdFixedWidthBinary;
    missingDevices?: number[];
    extraDevices?: number[];
    staleDevices?: number[];
  }) {
    this.account =
      account instanceof ServiceId
        ? account
        : ServiceId.parseFromServiceIdFixedWidthBinary(account);
    this.missingDevices = missingDevices ?? [];
    this.extraDevices = extraDevices ?? [];
    this.staleDevices = staleDevices ?? [];
  }
}

export class LibSignalErrorBase extends Error {
  public readonly code: ErrorCode;
  public readonly operation: string;
  readonly _addr?: string | Native.ProtocolAddress;

  constructor(
    message: string,
    name: keyof typeof ErrorCode | undefined,
    operation: string,
    extraProps?: Record<string, unknown>
  ) {
    super(message);
    // Include the dynamic check for `name in ErrorCode` in case there's a bug in the Rust code.
    if (name !== undefined && name in ErrorCode) {
      this.name = name;
      this.code = ErrorCode[name];
    } else {
      this.name = 'LibSignalError';
      this.code = ErrorCode.Generic;
    }
    this.operation = operation;
    if (extraProps !== undefined) {
      Object.assign(this, extraProps);
    }

    // Maintains proper stack trace, where our error was thrown (only available on V8)
    //   via https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this);
    }
  }

  public get addr(): ProtocolAddress | string {
    switch (this.code) {
      case ErrorCode.UntrustedIdentity:
        return this._addr as string;
      case ErrorCode.InvalidRegistrationId:
        return ProtocolAddress._fromNativeHandle(
          this._addr as Native.ProtocolAddress
        );
      default:
        throw new TypeError(`cannot get address from this error (${this})`);
    }
  }

  public toString(): string {
    return `${this.name} - ${this.operation}: ${this.message}`;
  }

  /// Like `error.code === code`, but also providing access to any additional properties.
  public is<E extends ErrorCode>(
    code: E
  ): this is Extract<LibSignalError, { code: E }> {
    return this.code === code;
  }

  /// Like `error instanceof LibSignalErrorBase && error.code === code`, but all in one expression,
  /// and providing access to any additional properties.
  public static is<E extends ErrorCode>(
    error: unknown,
    code: E
  ): error is Extract<LibSignalError, { code: E }> {
    if (error instanceof LibSignalErrorBase) {
      return error.is(code);
    }
    return false;
  }
}

export type LibSignalErrorCommon = Omit<LibSignalErrorBase, 'addr'>;

export type GenericError = LibSignalErrorCommon & {
  code: ErrorCode.Generic;
};

export type DuplicatedMessageError = LibSignalErrorCommon & {
  code: ErrorCode.DuplicatedMessage;
};

export type SealedSenderSelfSendError = LibSignalErrorCommon & {
  code: ErrorCode.SealedSenderSelfSend;
};

export type UntrustedIdentityError = LibSignalErrorCommon & {
  code: ErrorCode.UntrustedIdentity;
  addr: string;
};

export type InvalidRegistrationIdError = LibSignalErrorCommon & {
  code: ErrorCode.InvalidRegistrationId;
  addr: ProtocolAddress;
};

export type InvalidProtocolAddress = LibSignalErrorCommon & {
  code: ErrorCode.InvalidProtocolAddress;
  name: string;
  deviceId: number;
};

export type VerificationFailedError = LibSignalErrorCommon & {
  code: ErrorCode.VerificationFailed;
};

export type InvalidSessionError = LibSignalErrorCommon & {
  code: ErrorCode.InvalidSession;
};

export type InvalidSenderKeySessionError = LibSignalErrorCommon & {
  code: ErrorCode.InvalidSenderKeySession;
  distributionId: string;
};

export type NicknameCannotBeEmptyError = LibSignalErrorCommon & {
  code: ErrorCode.NicknameCannotBeEmpty;
};
export type CannotStartWithDigitError = LibSignalErrorCommon & {
  code: ErrorCode.CannotStartWithDigit;
};
export type MissingSeparatorError = LibSignalErrorCommon & {
  code: ErrorCode.MissingSeparator;
};

export type BadNicknameCharacterError = LibSignalErrorCommon & {
  code: ErrorCode.BadNicknameCharacter;
};

export type NicknameTooShortError = LibSignalErrorCommon & {
  code: ErrorCode.NicknameTooShort;
};

export type NicknameTooLongError = LibSignalErrorCommon & {
  code: ErrorCode.NicknameTooLong;
};

export type DiscriminatorCannotBeEmptyError = LibSignalErrorCommon & {
  code: ErrorCode.DiscriminatorCannotBeEmpty;
};
export type DiscriminatorCannotBeZeroError = LibSignalErrorCommon & {
  code: ErrorCode.DiscriminatorCannotBeZero;
};
export type DiscriminatorCannotBeSingleDigitError = LibSignalErrorCommon & {
  code: ErrorCode.DiscriminatorCannotBeSingleDigit;
};
export type DiscriminatorCannotHaveLeadingZerosError = LibSignalErrorCommon & {
  code: ErrorCode.DiscriminatorCannotHaveLeadingZeros;
};
export type BadDiscriminatorCharacterError = LibSignalErrorCommon & {
  code: ErrorCode.BadDiscriminatorCharacter;
};
export type DiscriminatorTooLargeError = LibSignalErrorCommon & {
  code: ErrorCode.DiscriminatorTooLarge;
};

export type InputDataTooLong = LibSignalErrorCommon & {
  code: ErrorCode.InputDataTooLong;
};

export type InvalidEntropyDataLength = LibSignalErrorCommon & {
  code: ErrorCode.InvalidEntropyDataLength;
};

export type InvalidUsernameLinkEncryptedData = LibSignalErrorCommon & {
  code: ErrorCode.InvalidUsernameLinkEncryptedData;
};

export type IoError = LibSignalErrorCommon & {
  code: ErrorCode.IoError;
};

export type CdsiInvalidTokenError = LibSignalErrorCommon & {
  code: ErrorCode.CdsiInvalidToken;
};

export type InvalidUriError = LibSignalErrorCommon & {
  code: ErrorCode.InvalidUri;
};

export type InvalidMediaInputError = LibSignalErrorCommon & {
  code: ErrorCode.InvalidMediaInput;
};

export type UnsupportedMediaInputError = LibSignalErrorCommon & {
  code: ErrorCode.UnsupportedMediaInput;
};

export type RateLimitedError = LibSignalErrorBase & {
  code: ErrorCode.RateLimitedError;
  readonly retryAfterSecs: number;
};

export type RateLimitChallengeError = LibSignalErrorBase & {
  code: ErrorCode.RateLimitChallengeError;
  readonly token: string;
  readonly options: Set<'pushChallenge' | 'captcha'>;
};

export type ChatServiceInactive = LibSignalErrorBase & {
  code: ErrorCode.ChatServiceInactive;
};

export type AppExpiredError = LibSignalErrorBase & {
  code: ErrorCode.AppExpired;
};

export type DeviceDelinkedError = LibSignalErrorBase & {
  code: ErrorCode.DeviceDelinked;
};

export type ConnectionInvalidatedError = LibSignalErrorBase & {
  code: ErrorCode.ConnectionInvalidated;
};

export type ConnectedElsewhereError = LibSignalErrorBase & {
  code: ErrorCode.ConnectedElsewhere;
};

export type SvrDataMissingError = LibSignalErrorBase & {
  code: ErrorCode.SvrDataMissing;
};

export type SvrRequestFailedError = LibSignalErrorCommon & {
  code: ErrorCode.SvrRequestFailed;
};

export type SvrRestoreFailedError = LibSignalErrorCommon & {
  code: ErrorCode.SvrRestoreFailed;
  readonly triesRemaining: number;
};

export type SvrAttestationError = LibSignalErrorCommon & {
  code: ErrorCode.SvrAttestationError;
};

export type SvrInvalidDataError = LibSignalErrorCommon & {
  code: ErrorCode.SvrInvalidData;
};

export type BackupValidationError = LibSignalErrorCommon & {
  code: ErrorCode.BackupValidation;
  readonly unknownFields: ReadonlyArray<string>;
};

export type CancellationError = LibSignalErrorCommon & {
  code: ErrorCode.Cancelled;
};

export type KeyTransparencyError = LibSignalErrorCommon & {
  code: ErrorCode.KeyTransparencyError;
};

export type KeyTransparencyVerificationFailed = LibSignalErrorCommon & {
  code: ErrorCode.KeyTransparencyVerificationFailed;
};

export type IncrementalMacVerificationFailed = LibSignalErrorCommon & {
  code: ErrorCode.IncrementalMacVerificationFailed;
};

export type RequestUnauthorizedError = LibSignalErrorCommon & {
  code: ErrorCode.RequestUnauthorized;
};

export type MismatchedDevicesError = LibSignalErrorCommon & {
  code: ErrorCode.MismatchedDevices;
  readonly entries: MismatchedDevicesEntry[];
};

export type LibSignalError =
  | GenericError
  | DuplicatedMessageError
  | SealedSenderSelfSendError
  | UntrustedIdentityError
  | InvalidRegistrationIdError
  | InvalidProtocolAddress
  | VerificationFailedError
  | InvalidSessionError
  | InvalidSenderKeySessionError
  | NicknameCannotBeEmptyError
  | CannotStartWithDigitError
  | MissingSeparatorError
  | BadNicknameCharacterError
  | NicknameTooShortError
  | NicknameTooLongError
  | DiscriminatorCannotBeEmptyError
  | DiscriminatorCannotBeZeroError
  | DiscriminatorCannotBeSingleDigitError
  | DiscriminatorCannotHaveLeadingZerosError
  | BadDiscriminatorCharacterError
  | DiscriminatorTooLargeError
  | InputDataTooLong
  | InvalidEntropyDataLength
  | InvalidUsernameLinkEncryptedData
  | IoError
  | CdsiInvalidTokenError
  | InvalidUriError
  | InvalidMediaInputError
  | SvrDataMissingError
  | SvrRestoreFailedError
  | SvrRequestFailedError
  | SvrAttestationError
  | SvrInvalidDataError
  | UnsupportedMediaInputError
  | ChatServiceInactive
  | AppExpiredError
  | DeviceDelinkedError
  | ConnectionInvalidatedError
  | ConnectedElsewhereError
  | RateLimitedError
  | RateLimitChallengeError
  | BackupValidationError
  | CancellationError
  | KeyTransparencyError
  | KeyTransparencyVerificationFailed
  | IncrementalMacVerificationFailed
  | RequestUnauthorizedError
  | MismatchedDevicesError;
