//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr2;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/** A hash of the pin that can be used to interact with a Secure Value Recovery service. */
public class PinHash extends NativeHandleGuard.SimpleOwner {
  private PinHash(final long nativeHandle) {
    super(nativeHandle);
  }

  @Override
  protected void release(long nativeHandle) {
    Native.PinHash_Destroy(nativeHandle);
  }

  /**
   * Hash a pin for use with a remote SecureValueRecovery1 service.
   *
   * <p>Note: This should be used with SVR1 only. For SVR1, the salt should be the backup id. For
   * SVR2 clients, use {@link PinHash#svr2} which handles salt selection internally.
   *
   * @param normalizedPin A normalized, UTF-8 encoded byte representation of the pin
   * @param salt A 32 byte salt
   * @return A {@link PinHash}
   */
  public static PinHash svr1(final byte[] normalizedPin, final byte[] salt) {
    return new PinHash(filterExceptions(() -> Native.PinHash_FromSalt(normalizedPin, salt)));
  }

  /**
   * Hash a pin for use with a remote SecureValueRecovery2 service.
   *
   * <p>Note: This should be used with SVR2 only. For SVR1 clients, use {@link PinHash#svr1}
   *
   * @param normalizedPin A normalized, UTF-8 encoded byte representation of the pin
   * @param username The Basic Auth username used to authenticate with SVR2
   * @param mrenclave The mrenclave where the hashed pin will be stored
   * @return A {@link PinHash}
   */
  public static PinHash svr2(
      final byte[] normalizedPin, final String username, final byte[] mrenclave) {
    return new PinHash(
        filterExceptions(
            () -> Native.PinHash_FromUsernameMrenclave(normalizedPin, username, mrenclave)));
  }

  /**
   * A key that can be used to encrypt or decrypt values before uploading them to a secure store.
   *
   * @return a 32 byte encryption key
   */
  public byte[] encryptionKey() {
    return guardedMap(Native::PinHash_EncryptionKey);
  }

  /**
   * A secret that can be used to access a value in a secure store.
   *
   * @return a 32 byte access key
   */
  public byte[] accessKey() {
    return guardedMap(Native::PinHash_AccessKey);
  }
}
