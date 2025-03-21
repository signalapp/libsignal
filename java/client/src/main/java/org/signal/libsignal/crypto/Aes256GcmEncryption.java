//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;

public class Aes256GcmEncryption extends NativeHandleGuard.SimpleOwner {
  public Aes256GcmEncryption(byte[] key, byte[] nonce, byte[] associatedData)
      throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.Aes256GcmEncryption_New(key, nonce, associatedData)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.Aes256GcmEncryption_Destroy(nativeHandle);
  }

  public void encrypt(byte[] plaintext, int offset, int length) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmEncryption_Update(nativeHandle, plaintext, offset, length));
  }

  public void encrypt(byte[] plaintext) {
    guardedRun(
        (nativeHandle) ->
            Native.Aes256GcmEncryption_Update(nativeHandle, plaintext, 0, plaintext.length));
  }

  public byte[] computeTag() {
    return guardedMap(Native::Aes256GcmEncryption_ComputeTag);
  }
}
