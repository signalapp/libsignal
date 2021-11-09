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
}

export class SignalClientErrorBase extends Error {
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
      this.name = 'SignalClientError';
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

export type SignalClientErrorCommon = Omit<SignalClientErrorBase, 'addr'>;

export type GenericError = SignalClientErrorCommon & {
  code: ErrorCode.Generic;
};

export type DuplicatedMessageError = SignalClientErrorCommon & {
  code: ErrorCode.DuplicatedMessage;
};

export type SealedSenderSelfSendError = SignalClientErrorCommon & {
  code: ErrorCode.SealedSenderSelfSend;
};

export type UntrustedIdentityError = SignalClientErrorCommon & {
  code: ErrorCode.UntrustedIdentity;
  addr: string;
};

export type InvalidRegistrationIdError = SignalClientErrorCommon & {
  code: ErrorCode.InvalidRegistrationId;
  addr: ProtocolAddress;
};

export type VerificationFailedError = SignalClientErrorCommon & {
  code: ErrorCode.VerificationFailed;
};

export type SignalClientError =
  | GenericError
  | DuplicatedMessageError
  | SealedSenderSelfSendError
  | UntrustedIdentityError
  | InvalidRegistrationIdError
  | VerificationFailedError;
