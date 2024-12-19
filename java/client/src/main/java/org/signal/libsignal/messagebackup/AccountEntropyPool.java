//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;

/**
 * The randomly-generated user-memorized entropy used to derive the backup key, with other possible
 * future uses.
 */
public class AccountEntropyPool {
  /**
   * Generate a new entropy pool and return the canonical string representation.
   *
   * <p>This pool contains log_2(36^64) = ~330 bits of cryptographic quality randomness.
   *
   * @return A 64 character string containing randomly chosen digits from [a-z0-9].
   */
  public static String generate() {
    return filterExceptions(() -> Native.AccountEntropyPool_Generate());
  }

  /**
   * Checks whether a string can be used as an account entropy pool.
   *
   * @return <code>true</code> if the string is a structurally valid account entropy value.
   */
  public static boolean isValid(String accountEntropyPool) {
    return Native.AccountEntropyPool_IsValid(accountEntropyPool);
  }

  /**
   * Derives an SVR key from the given account entropy pool.
   *
   * <p>{@code accountEntropyPool} must be a **validated** account entropy pool; passing an
   * arbitrary string here is considered a programmer error.
   */
  public static byte[] deriveSvrKey(String accountEntropyPool) {
    return Native.AccountEntropyPool_DeriveSvrKey(accountEntropyPool);
  }

  /**
   * Derives a backup key from the given account entropy pool.
   *
   * <p>{@code accountEntropyPool} must be a **validated** account entropy pool; passing an
   * arbitrary string here is considered a programmer error.
   *
   * @see BackupKey#generateRandom
   */
  public static BackupKey deriveBackupKey(String accountEntropyPool) {
    return filterExceptions(
        () -> new BackupKey(Native.AccountEntropyPool_DeriveBackupKey(accountEntropyPool)));
  }
}
