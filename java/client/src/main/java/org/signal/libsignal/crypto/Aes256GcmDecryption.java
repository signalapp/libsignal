//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class Aes256GcmDecryption extends NativeHandleGuard.SimpleOwner {
  public static final int TAG_SIZE_IN_BYTES = 16;

  public Aes256GcmDecryption(byte[] key, byte[] nonce, byte[] associatedData)
      throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.Aes256GcmDecryption_New(key, nonce, associatedData)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.Aes256GcmDecryption_Destroy(nativeHandle);
  }

  public void decrypt(byte[] plaintext) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmDecryption_Update(nativeHandle, plaintext, 0, plaintext.length));
  }

  public void decrypt(byte[] plaintext, int offset, int length) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmDecryption_Update(nativeHandle, plaintext, offset, length));
  }

  public boolean verifyTag(byte[] tag) {
    return guardedMap(
        (nativeHandle) ->
            filterExceptions(() -> Native.Aes256GcmDecryption_VerifyTag(nativeHandle, tag)));
  }
}
