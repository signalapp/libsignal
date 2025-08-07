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

public class KEMPublicKey :
  NativeHandleGuard.SimpleOwner,
  SerializablePublicKey {
  @Deprecated("use the constructor that takes an offset and length")
  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray, offset: Int) :
    this(serialized, offset, length = serialized.size - offset)

  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray, offset: Int, length: Int) :
    super(Native.KyberPublicKey_DeserializeWithOffsetLength(serialized, offset, length))

  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray) : this(serialized, 0, serialized.size)

  public constructor(nativeHandle: Long) : super(NativeHandleGuard.SimpleOwner.throwIfNull(nativeHandle))

  protected override fun release(nativeHandle: Long) {
    Native.KyberPublicKey_Destroy(nativeHandle)
  }

  public fun serialize(): ByteArray = guardedMapChecked(Native::KyberPublicKey_Serialize)

  public override fun equals(other: Any?): Boolean =
    when (other) {
      null -> false
      is KEMPublicKey ->
        guardedMap { thisNativeHandle ->
          other.guardedMap { otherNativeHandle ->
            Native.KyberPublicKey_Equals(thisNativeHandle, otherNativeHandle)
          }
        }
      else -> false
    }

  public override fun hashCode(): Int = Arrays.hashCode(this.serialize())
}
