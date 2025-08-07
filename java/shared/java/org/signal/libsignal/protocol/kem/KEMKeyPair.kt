//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard

public class KEMKeyPair(
  nativeHandle: Long,
) : NativeHandleGuard.SimpleOwner(
    NativeHandleGuard.SimpleOwner.throwIfNull(nativeHandle),
  ) {
  public companion object {
    @JvmStatic
    public fun generate(reserved: KEMKeyType): KEMKeyPair =
      when (reserved) {
        KEMKeyType.KYBER_1024 -> KEMKeyPair(Native.KyberKeyPair_Generate())
      }
  }

  protected override fun release(nativeHandle: Long) {
    Native.KyberKeyPair_Destroy(nativeHandle)
  }

  public val publicKey: KEMPublicKey
    get() = KEMPublicKey(guardedMap(Native::KyberKeyPair_GetPublicKey))

  public val secretKey: KEMSecretKey
    get() = KEMSecretKey(guardedMap(Native::KyberKeyPair_GetSecretKey))
}
