//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.crypto;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;

public class Aes256GcmSiv extends NativeHandleGuard.SimpleOwner {

  public Aes256GcmSiv(byte[] key) throws InvalidKeyException {
    super(filterExceptions(InvalidKeyException.class, () -> Native.Aes256GcmSiv_New(key)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.Aes256GcmSiv_Destroy(nativeHandle);
  }

  public byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] associated_data) {
    return filterExceptions(
        () ->
            guardedMapChecked(
                nativeHandle ->
                    Native.Aes256GcmSiv_Encrypt(nativeHandle, plaintext, nonce, associated_data)));
  }

  public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] associated_data)
      throws InvalidMessageException {
    return filterExceptions(
        InvalidMessageException.class,
        () ->
            guardedMapChecked(
                (nativeHandle) ->
                    Native.Aes256GcmSiv_Decrypt(nativeHandle, ciphertext, nonce, associated_data)));
  }
}
