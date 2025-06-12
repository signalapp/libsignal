//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.InvalidKeyException

public class ECPrivateKey : NativeHandleGuard.SimpleOwner {
  companion object {
    @JvmStatic
    public fun generate(): ECPrivateKey {
      return ECPrivateKey(Native.ECPrivateKey_Generate())
    }
  }

  @Throws(InvalidKeyException::class)
  public constructor(privateKey: ByteArray) : this(Native.ECPrivateKey_Deserialize(privateKey))

  public constructor(nativeHandle: Long) : super(nativeHandle)

  protected override fun release(nativeHandle: Long) {
    Native.ECPrivateKey_Destroy(nativeHandle)
  }

  public fun serialize(): ByteArray {
    return guardedMapChecked(Native::ECPrivateKey_Serialize)
  }

  public fun calculateSignature(message: ByteArray): ByteArray {
    return guardedMap { Native.ECPrivateKey_Sign(it, message) }
  }

  public fun calculateAgreement(other: ECPublicKey): ByteArray {
    return this.guardedMap { privateKey ->
      other.guardedMap { publicKey ->
        Native.ECPrivateKey_Agree(privateKey, publicKey)
      }
    }
  }

  @JvmName("publicKey")
  public fun getPublicKey(): ECPublicKey {
    return ECPublicKey(guardedMapChecked(Native::ECPrivateKey_GetPublicKey))
  }
}
