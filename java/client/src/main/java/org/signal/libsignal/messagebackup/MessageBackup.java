//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

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

  /** Validates an encrypted message backup bundle. */
  public static ValidationResult validate(
      MessageBackupKey key, Supplier<InputStream> streamFactory, long streamLength)
      throws ValidationError, IOException {
    InputStream first = streamFactory.get();
    InputStream second = streamFactory.get();

    Pair<String, String[]> result;
    try (NativeHandleGuard keyGuard = new NativeHandleGuard(key)) {

      Object output =
          Native.MessageBackupValidator_Validate(
              keyGuard.nativeHandle(), first, second, streamLength);

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
