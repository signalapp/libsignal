//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

export enum ErrorCode {
  Generic,
  UntrustedIdentity,
  SealedSenderSelfSend,
}

export class SignalClientErrorBase extends Error {
  public readonly code: ErrorCode;
  public readonly operation: string;

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
}

export type GenericError = SignalClientErrorBase & {
  code: ErrorCode.Generic;
};

export type UntrustedIdentityError = SignalClientErrorBase & {
  code: ErrorCode.UntrustedIdentity;
  addr: string;
};

export type SealedSenderSelfSendError = SignalClientErrorBase & {
  code: ErrorCode.SealedSenderSelfSend;
};

export type SignalClientError =
  | GenericError
  | UntrustedIdentityError
  | SealedSenderSelfSendError;
