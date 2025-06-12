//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.SerializablePublicKey
import java.util.Arrays

public final class ECPublicKey : NativeHandleGuard.SimpleOwner, Comparable<ECPublicKey>, SerializablePublicKey {
  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray, offset: Int) : this(Native.ECPublicKey_Deserialize(serialized, offset))

  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray) : this(Native.ECPublicKey_Deserialize(serialized, 0))

  companion object {
    public const val KEY_SIZE = 33

    @JvmStatic
    @Throws(InvalidKeyException::class)
    public fun fromPublicKeyBytes(key: ByteArray): ECPublicKey {
      if (key.size != KEY_SIZE - 1) {
        throw InvalidKeyException("invalid number of public key bytes (expected ${KEY_SIZE - 1}, was ${key.size}")
      }
      val withType = ByteArray(KEY_SIZE)
      withType[0] = 0x05
      key.copyInto(withType, destinationOffset = 1)
      return ECPublicKey(Native.ECPublicKey_Deserialize(withType, 0))
    }
  }

  public constructor(nativeHandle: Long) : super(nativeHandle) {
    if (nativeHandle == 0L) {
      throw NullPointerException()
    }
  }

  protected override fun release(nativeHandle: Long) {
    if (nativeHandle != 0L) {
      Native.ECPublicKey_Destroy(nativeHandle)
    }
  }

  public fun verifySignature(message: ByteArray, signature: ByteArray): Boolean {
    return guardedMap { Native.ECPublicKey_Verify(it, message, signature) }
  }

  public fun serialize(): ByteArray {
    return guardedMap(Native::ECPublicKey_Serialize)
  }

  public val publicKeyBytes: ByteArray
    get() = guardedMap(Native::ECPublicKey_GetPublicKeyBytes)

  public val type: Int
    get() = this.serialize()[0].toInt()

  override fun equals(other: Any?): Boolean {
    return when (other) {
      null -> false
      is ECPublicKey -> this.guardedMap { thisHandle ->
        other.guardedMap { thatHandle ->
          Native.ECPublicKey_Equals(thisHandle, thatHandle)
        }
      }
      else -> false
    }
  }

  public override fun hashCode(): Int {
    return Arrays.hashCode(this.serialize())
  }

  public override fun compareTo(other: ECPublicKey): Int {
    return this.guardedMap { thisHandle ->
      other.guardedMap { otherHandle ->
        Native.ECPublicKey_Compare(thisHandle, otherHandle)
      }
    }
  }
}
