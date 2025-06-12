//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.SerializablePublicKey
import java.util.Arrays

public class KEMPublicKey : NativeHandleGuard.SimpleOwner, SerializablePublicKey {

  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray, offset: Int) :
    super(Native.KyberPublicKey_DeserializeWithOffset(serialized, offset))

  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray) : this(serialized, 0)

  public constructor(nativeHandle: Long) : super(NativeHandleGuard.SimpleOwner.throwIfNull(nativeHandle))

  protected override fun release(nativeHandle: Long) {
    Native.KyberPublicKey_Destroy(nativeHandle)
  }

  public fun serialize(): ByteArray {
    return guardedMapChecked(Native::KyberPublicKey_Serialize)
  }

  public override fun equals(other: Any?): Boolean {
    return when (other) {
      null -> false
      is KEMPublicKey ->
        guardedMap { thisNativeHandle ->
          other.guardedMap { otherNativeHandle ->
            Native.KyberPublicKey_Equals(thisNativeHandle, otherNativeHandle)
          }
        }
      else -> false
    }
  }

  public override fun hashCode(): Int {
    return Arrays.hashCode(this.serialize())
  }
}
