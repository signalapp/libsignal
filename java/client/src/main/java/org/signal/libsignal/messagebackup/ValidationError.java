//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

/**
 * Error from validating a message backup bundle.
 *
 * <p>{@link Throwable#getMessage} returns the validation error message.
 */
public class ValidationError extends Exception {
  /** Contains messages about unknown fields found while parsing. */
  public String[] unknownFieldMessages;

  ValidationError(String message, String[] unknownFields) {
    super(message);
    this.unknownFieldMessages = unknownFields;
  }
}
