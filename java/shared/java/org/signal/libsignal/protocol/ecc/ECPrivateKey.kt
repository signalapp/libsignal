//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.InvalidKeyException
import org.signal.libsignal.protocol.InvalidMessageException

public class ECPrivateKey : NativeHandleGuard.SimpleOwner {
  public companion object {
    @JvmStatic
    public fun generate(): ECPrivateKey = ECPrivateKey(Native.ECPrivateKey_Generate())
  }

  @Throws(InvalidKeyException::class)
  public constructor(privateKey: ByteArray) : this(Native.ECPrivateKey_Deserialize(privateKey))

  public constructor(nativeHandle: Long) : super(nativeHandle)

  protected override fun release(nativeHandle: Long) {
    Native.ECPrivateKey_Destroy(nativeHandle)
  }

  public fun serialize(): ByteArray = guardedMapChecked(Native::ECPrivateKey_Serialize)

  public fun calculateSignature(message: ByteArray): ByteArray = guardedMap { Native.ECPrivateKey_Sign(it, message) }

  public fun calculateAgreement(other: ECPublicKey): ByteArray =
    this.guardedMap { privateKey ->
      other.guardedMap { publicKey ->
        Native.ECPrivateKey_Agree(privateKey, publicKey)
      }
    }

  /**
   * Opens a ciphertext sealed with [PublicKey.seal(ByteArray,ByteArray,ByteArray)].
   *
   * Uses HPKE ([RFC 9180][]). The input should include its original type byte indicating the
   * chosen algorithms and ciphertext layout. The `info` and `associatedData` must match those
   * used during sealing.
   *
   * @throws InvalidMessageException if the ciphertext is valid but can't be decrypted
   * @throws IllegalArgumentException if the ciphertext is malformed
   *
   * [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
   */
  @Throws(InvalidMessageException::class, IllegalArgumentException::class)
  public fun open(
    ciphertext: ByteArray,
    info: ByteArray,
    associatedData: ByteArray = byteArrayOf(),
  ): ByteArray = guardedMap { Native.ECPrivateKey_HpkeOpen(it, ciphertext, info, associatedData) }

  /** A convenience overload of [open(ByteArray,ByteArray,ByteArray)], using the UTF-8 bytes of `info`. */
  @Throws(InvalidMessageException::class, IllegalArgumentException::class)
  public fun open(
    ciphertext: ByteArray,
    info: String,
    associatedData: ByteArray = byteArrayOf(),
  ): ByteArray = open(ciphertext, info.toByteArray(), associatedData)

  @JvmName("publicKey")
  public fun getPublicKey(): ECPublicKey = ECPublicKey(guardedMapChecked(Native::ECPrivateKey_GetPublicKey))
}
