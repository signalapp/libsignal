//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { ProtocolAddress } from './Address';
import * as Native from '../Native';

export enum ErrorCode {
  Generic,

  DuplicatedMessage,
  SealedSenderSelfSend,
  UntrustedIdentity,
  InvalidRegistrationId,
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

  SvrDataMissing,
  SvrRequestFailed,
  SvrRestoreFailed,

  ChatServiceInactive,
  AppExpired,
  DeviceDelinked,

  BackupValidation,

  Cancelled,
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

export type ChatServiceInactive = LibSignalErrorBase & {
  code: ErrorCode.ChatServiceInactive;
};

export type AppExpiredError = LibSignalErrorBase & {
  code: ErrorCode.AppExpired;
};

export type DeviceDelinkedError = LibSignalErrorBase & {
  code: ErrorCode.DeviceDelinked;
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

export type BackupValidationError = LibSignalErrorCommon & {
  code: ErrorCode.BackupValidation;
  readonly unknownFields: ReadonlyArray<string>;
};

export type CancellationError = LibSignalErrorCommon & {
  code: ErrorCode.Cancelled;
};

export type LibSignalError =
  | GenericError
  | DuplicatedMessageError
  | SealedSenderSelfSendError
  | UntrustedIdentityError
  | InvalidRegistrationIdError
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
  | UnsupportedMediaInputError
  | ChatServiceInactive
  | AppExpiredError
  | DeviceDelinkedError
  | RateLimitedError
  | BackupValidationError
  | CancellationError;
