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

  CannotBeEmpty,
  CannotStartWithDigit,
  MissingSeparator,
  BadNicknameCharacter,
  NicknameTooShort,
  NicknameTooLong,

  IoError,

  InvalidMediaInput,
  UnsupportedMediaInput,

  InputDataTooLong,
  InvalidEntropyDataLength,
  InvalidUsernameLinkEncryptedData,
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

export type CannotBeEmptyError = LibSignalErrorCommon & {
  code: ErrorCode.CannotBeEmpty;
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

export type InvalidMediaInputError = LibSignalErrorCommon & {
  code: ErrorCode.InvalidMediaInput;
};

export type UnsupportedMediaInputError = LibSignalErrorCommon & {
  code: ErrorCode.UnsupportedMediaInput;
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
  | CannotBeEmptyError
  | CannotStartWithDigitError
  | MissingSeparatorError
  | BadNicknameCharacterError
  | NicknameTooShortError
  | NicknameTooLongError
  | InputDataTooLong
  | InvalidEntropyDataLength
  | InvalidUsernameLinkEncryptedData
  | IoError
  | InvalidMediaInputError
  | UnsupportedMediaInputError;
