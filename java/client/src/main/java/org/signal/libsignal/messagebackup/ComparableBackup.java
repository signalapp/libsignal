//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.io.IOException;
import java.io.InputStream;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;

/**
 * An in-memory representation of a backup file used to compare contents.
 *
 * <p>When comparing the contents of two backups:
 *
 * <ol>
 *   <li>Create a `ComparableBackup` instance for each of the inputs.
 *   <li>Check the `unknownFields()` value; if it's not empty, some parts of the backup weren't
 *       parsed and won't be compared.
 *   <li>Produce a canonical string for each backup with `comparableString()`.
 * </ol>
 *
 * Compare the canonical string representations. The diff of the canonical strings (which may be
 * rather large) will show the differences between the logical content of the input backup files.
 */
public class ComparableBackup implements NativeHandleGuard.Owner {
  /**
   * Reads an unencrypted message backup bundle into memory for comparison.
   *
   * <p>Returns an error if the input cannot be read or if validation fails.
   *
   * @param purpose whether the input was created for device-to-device transfer or remote backup
   * @param input an <code>InputStream</code> that produces the input
   * @param streamLength the number of bytes each <code>InputStream</code> will produce
   * @throws ValidationError with an error message if the input is invalid
   * @throws IOException if the input could not be read
   */
  public static ComparableBackup readUnencrypted(
      MessageBackup.Purpose purpose, InputStream input, long streamLength)
      throws ValidationError, IOException {

    long handle =
        filterExceptions(
            IOException.class,
            ValidationError.class,
            () ->
                NativeTesting.ComparableBackup_ReadUnencrypted(
                    input, streamLength, purpose.ordinal()));

    return new ComparableBackup(handle);
  }

  /**
   * Produces a string representation of the contents.
   *
   * <p>The returned strings for two backups will be equal if the backups contain the same logical
   * content. If two backups' strings are not equal, the diff will show what is different between
   * them.
   *
   * @return a canonical string representation of the backup
   */
  public String getComparableString() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> NativeTesting.ComparableBackup_GetComparableString(guard.nativeHandle()));
    }
  }

  /**
   * Returns the unrecognized protobuf fields present in the backup.
   *
   * <p>If the returned array is not empty, some parts of the backup were not recognized and won't
   * be present in the string representation.
   *
   * @return information about each unknown field found in the backup
   */
  public String[] getUnknownFieldMessages() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return (String[])
          filterExceptions(
              () -> NativeTesting.ComparableBackup_GetUnknownFields(guard.nativeHandle()));
    }
  }

  @CalledFromNative
  private ComparableBackup(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    NativeTesting.ComparableBackup_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
