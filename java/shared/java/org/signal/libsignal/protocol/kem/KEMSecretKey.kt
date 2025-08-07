//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kem

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.InvalidKeyException

public class KEMSecretKey(
  nativeHandle: Long,
) : NativeHandleGuard.SimpleOwner(
    NativeHandleGuard.SimpleOwner.throwIfNull(nativeHandle),
  ) {
  @Throws(InvalidKeyException::class)
  public constructor(privateKey: ByteArray) : this(
    Native.KyberSecretKey_Deserialize(privateKey),
  )

  protected override fun release(nativeHandle: Long) {
    Native.KyberSecretKey_Destroy(nativeHandle)
  }

  public fun serialize(): ByteArray = guardedMapChecked(Native::KyberSecretKey_Serialize)
}
