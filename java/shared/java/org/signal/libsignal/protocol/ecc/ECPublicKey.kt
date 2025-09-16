//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc

import org.signal.libsignal.internal.CalledFromNative
import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.SerializablePublicKey
import java.util.Arrays

public final class ECPublicKey :
  NativeHandleGuard.SimpleOwner,
  Comparable<ECPublicKey>,
  SerializablePublicKey {
  @Deprecated("use the constructor that takes an offset and length")
  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray, offset: Int) : this(serialized, offset, length = serialized.size - offset)

  @Throws(InvalidKeyException::class)
  public constructor(serialized: ByteArray) : this(serialized, 0, serialized.size)

  @Throws(InvalidKeyException::class)
  public constructor(
    serialized: ByteArray,
    offset: Int,
    length: Int,
  ) : this(Native.ECPublicKey_Deserialize(serialized, offset, length))

  public companion object {
    public const val KEY_SIZE: Int = 33

    @JvmStatic
    @Throws(InvalidKeyException::class)
    public fun fromPublicKeyBytes(key: ByteArray): ECPublicKey {
      if (key.size != KEY_SIZE - 1) {
        throw InvalidKeyException("invalid number of public key bytes (expected ${KEY_SIZE - 1}, was ${key.size}")
      }
      val withType = ByteArray(KEY_SIZE)
      withType[0] = 0x05
      key.copyInto(withType, destinationOffset = 1)
      return ECPublicKey(withType)
    }
  }

  @CalledFromNative
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

  public fun verifySignature(
    message: ByteArray,
    signature: ByteArray,
  ): Boolean =
    guardedMap {
      Native.ECPublicKey_Verify(it, message, signature)
    }

  /**
   * Seals a message so only the holder of the private key can decrypt it.
   *
   * Uses HPKE ([RFC 9180][]). The output will include a type byte indicating the chosen
   * algorithms and ciphertext layout. The `info` parameter should typically be a static value
   * describing the purpose of the message, while `associatedData` can be used to restrict
   * successful decryption beyond holding the private key.
   *
   * @see ECPrivateKey.open
   *
   * [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
   */
  public fun seal(
    message: ByteArray,
    info: ByteArray,
    associatedData: ByteArray = byteArrayOf(),
  ): ByteArray = guardedMap { Native.ECPublicKey_HpkeSeal(it, message, info, associatedData) }

  /** A convenience overload of [seal(ByteArray,ByteArray,ByteArray)], using the UTF-8 bytes of `info`. */
  public fun seal(
    message: ByteArray,
    info: String,
    associatedData: ByteArray = byteArrayOf(),
  ): ByteArray = seal(message, info.toByteArray(), associatedData)

  public fun serialize(): ByteArray = guardedMap(Native::ECPublicKey_Serialize)

  public val publicKeyBytes: ByteArray
    get() = guardedMap(Native::ECPublicKey_GetPublicKeyBytes)

  public val type: Int
    get() = this.serialize()[0].toInt()

  override fun equals(other: Any?): Boolean =
    when (other) {
      null -> false
      is ECPublicKey ->
        this.guardedMap { thisHandle ->
          other.guardedMap { thatHandle ->
            Native.ECPublicKey_Equals(thisHandle, thatHandle)
          }
        }
      else -> false
    }

  public override fun hashCode(): Int = Arrays.hashCode(this.serialize())

  public override fun compareTo(other: ECPublicKey): Int =
    this.guardedMap { thisHandle ->
      other.guardedMap { otherHandle ->
        Native.ECPublicKey_Compare(thisHandle, otherHandle)
      }
    }
}
