//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.Arrays;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.SerializablePublicKey;

public class KEMPublicKey extends NativeHandleGuard.SimpleOwner implements SerializablePublicKey {

  public KEMPublicKey(byte[] serialized, int offset) throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.KyberPublicKey_DeserializeWithOffset(serialized, offset)));
  }

  public KEMPublicKey(byte[] serialized) throws InvalidKeyException {
    super(
        filterExceptions(
            InvalidKeyException.class,
            () -> Native.KyberPublicKey_DeserializeWithOffset(serialized, 0)));
  }

  public KEMPublicKey(long nativeHandle) {
    super(KEMPublicKey.throwIfNull(nativeHandle));
  }

  private static long throwIfNull(long handle) {
    if (handle == 0) {
      throw new NullPointerException();
    }
    return handle;
  }

  @Override
  protected void release(long nativeHandle) {
    Native.KyberPublicKey_Destroy(nativeHandle);
  }

  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::KyberPublicKey_Serialize));
  }

  @Override
  public boolean equals(Object other) {
    if (other == null) return false;
    if (!(other instanceof KEMPublicKey)) return false;
    return guardedMap(
        (thisNativeHandle) ->
            ((KEMPublicKey) other)
                .guardedMap(
                    (otherNativeHandle) ->
                        Native.KyberPublicKey_Equals(thisNativeHandle, otherNativeHandle)));
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.serialize());
  }
}
