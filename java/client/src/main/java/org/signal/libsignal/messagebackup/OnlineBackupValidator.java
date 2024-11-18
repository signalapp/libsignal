//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * An alternative to {@link MessageBackup#validate} that validates a backup frame-by-frame.
 *
 * <p>This is much faster than using {@code MessageBackup.validate()} because it bypasses the
 * decryption and decompression steps, but that also means it's validating less. Don't forget to
 * call {@code close()} or use try-with-resources syntax!
 *
 * <p>Unlike {@code MessageBackup.validate()}, unknown fields are treated as "soft" errors and
 * logged, rather than collected and returned to the app for processing.
 *
 * <h2>Example</h2>
 *
 * <pre>
 * const validator = new OnlineBackupValidator(
 *     backupInfoProto.serialize(),
 *     MessageBackup.Purpose.DEVICE_TRANSFER)
 * repeat {
 *   // ...generate Frames...
 *   validator.addFrame(frameProto.serialize())
 * }
 * validator.finalize() // don't forget this!
 * </pre>
 */
public class OnlineBackupValidator extends NativeHandleGuard.SimpleOwner implements AutoCloseable {
  /**
   * Initializes an OnlineBackupValidator from the given BackupInfo protobuf message.
   *
   * <p>"Soft" errors will be logged, including unrecognized fields in the protobuf.
   *
   * @throws ValidationError on error
   */
  public OnlineBackupValidator(byte[] backupInfo, MessageBackup.Purpose purpose)
      throws ValidationError {
    super(
        filterExceptions(
            ValidationError.class,
            () -> Native.OnlineBackupValidator_New(backupInfo, purpose.ordinal())));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.OnlineBackupValidator_Destroy(nativeHandle);
  }

  /**
   * Processes a single Frame protobuf message.
   *
   * <p>"Soft" errors will be logged, including unrecognized fields in the protobuf.
   *
   * @throws ValidationError on error
   */
  public void addFrame(byte[] frame) throws ValidationError {
    filterExceptions(
        ValidationError.class,
        () -> guardedRunChecked(h -> Native.OnlineBackupValidator_AddFrame(h, frame)));
  }

  /**
   * Marks that a backup is complete, and does any final checks that require whole-file knowledge.
   *
   * <p>"Soft" errors will be logged.
   *
   * @throws ValidationError on error
   */
  @Override
  public void close() throws ValidationError {
    filterExceptions(
        ValidationError.class,
        () -> guardedRunChecked(h -> Native.OnlineBackupValidator_Finalize(h)));
  }
}
