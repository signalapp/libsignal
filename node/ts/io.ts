//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';
import type { IoError } from './Errors.js';

/**
 * An abstract class representing an input stream of bytes.
 */
export abstract class InputStream implements Native.InputStream {
  _read(amount: number): Promise<Uint8Array> {
    return this.read(amount);
  }

  _skip(amount: number): Promise<void> {
    return this.skip(amount);
  }

  /**
   * Called to indicate the stream's resources should be released.
   *
   * The default implementation does nothing and completes immediately. Subclasses should not expect
   */
  close(): Promise<void> {
    return Promise.resolve();
  }

  /**
   * Read an amount of bytes from the input stream.
   *
   * The actual amount of bytes returned may be smaller than the amount requested by the caller, for any reason;
   * however, returning zero bytes always indicates that the end of the stream has been reached.
   *
   * @param amount The amount of bytes to read.
   * @returns A promise yielding a {@link Uint8Array} containing the read bytes.
   * @throws {IoError} If an I/O error occurred while reading from the input.
   */
  abstract read(amount: number): Promise<Uint8Array>;

  /**
   * Skip an amount of bytes in the input stream.
   *
   * If the requested number of bytes could not be skipped for any reason, an {@link IoError} must be raised instead.
   *
   * @param amount The amount of bytes to skip.
   * @returns A promise which is resolved once the bytes have been skipped.
   * @throws {IoError} If an I/O error occurred while skipping the bytes in the input.
   */
  abstract skip(amount: number): Promise<void>;
}
