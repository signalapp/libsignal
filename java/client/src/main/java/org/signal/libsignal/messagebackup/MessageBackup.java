//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.io.IOException;
import java.io.InputStream;
import java.util.function.Supplier;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.util.Pair;

/** Message-backup-related functionality. */
public class MessageBackup {

  /**
   * Result produced on a successful validation.
   *
   * <p>Contains information about non-fatal validation issues.
   */
  public static class ValidationResult {
    public ValidationResult(String[] unknownFieldMessages) {
      this.unknownFieldMessages = unknownFieldMessages;
    }

    /** Information about unknown fields encountered while validating. */
    public String[] unknownFieldMessages;
  }

  public static enum Purpose {
    // This needs to be kept in sync with the corresponding Rust enum.
    DEVICE_TRANSFER,
    REMOTE_BACKUP,
  }

  /**
   * Validates an encrypted message backup bundle.
   *
   * <p>Returns an error if the input cannot be read or if validation fails.
   *
   * @param key the key to use to decrypt the backup
   * @param purpose whether the input was created for device-to-device transfer or remote backup
   * @param streamFactory a factory for <code>InputStream</code>s that produce the input
   * @param streamLength the number of bytes each <code>InputStream</code> will produce
   * @return informational result about the successful validation
   * @throws ValidationError with an error message if the input is invalid
   * @throws IOException if the input could not be read
   * @see OnlineBackupValidator
   */
  public static ValidationResult validate(
      MessageBackupKey key, Purpose purpose, Supplier<InputStream> streamFactory, long streamLength)
      throws ValidationError, IOException {
    InputStream first = streamFactory.get();
    InputStream second = streamFactory.get();

    Pair<String, String[]> result;
    try (NativeHandleGuard keyGuard = new NativeHandleGuard(key)) {

      Object output =
          filterExceptions(
              IOException.class,
              ValidationError.class,
              () ->
                  Native.MessageBackupValidator_Validate(
                      keyGuard.nativeHandle(), first, second, streamLength, purpose.ordinal()));

      // Rust conversion code is generating an instance of this class.
      @SuppressWarnings("unchecked")
      Pair<String, String[]> outputPair = (Pair<String, String[]>) output;
      result = outputPair;
    }

    String errorMessage = result.first();
    if (errorMessage != null) {
      throw new ValidationError(errorMessage, result.second());
    }

    return new ValidationResult(result.second());
  }
}
