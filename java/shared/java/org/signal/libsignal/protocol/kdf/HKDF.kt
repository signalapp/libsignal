//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.protocol.kdf

import org.signal.libsignal.internal.Native

public object HKDF {
  @JvmStatic
  public fun deriveSecrets(
    inputKeyMaterial: ByteArray,
    info: ByteArray,
    outputLength: Int,
  ): ByteArray = Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, null)

  @JvmStatic
  public fun deriveSecrets(
    inputKeyMaterial: ByteArray,
    salt: ByteArray,
    info: ByteArray?,
    outputLength: Int,
  ): ByteArray = Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, salt)
}
