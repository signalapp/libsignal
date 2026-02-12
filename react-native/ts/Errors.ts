//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Signal Protocol error types.
 */

export enum ErrorCode {
  Generic = 0,
  InvalidArgument = 1,
  InvalidState = 2,
  InternalError = 3,
  InvalidKey = 4,
  InvalidSignature = 5,
  ProtocolError = 6,
  CryptoError = 7,
}

/**
 * Base error class for libsignal errors.
 */
export class LibSignalError extends Error {
  readonly code: ErrorCode;

  constructor(message: string, code: ErrorCode = ErrorCode.Generic) {
    super(message);
    this.name = 'LibSignalError';
    this.code = code;
  }
}

/**
 * Thrown when a cryptographic operation fails (invalid key, bad signature, etc.)
 */
export class InvalidKeyError extends LibSignalError {
  constructor(message: string) {
    super(message, ErrorCode.InvalidKey);
    this.name = 'InvalidKeyError';
  }
}

/**
 * Thrown when a signature verification fails.
 */
export class InvalidSignatureError extends LibSignalError {
  constructor(message: string) {
    super(message, ErrorCode.InvalidSignature);
    this.name = 'InvalidSignatureError';
  }
}
