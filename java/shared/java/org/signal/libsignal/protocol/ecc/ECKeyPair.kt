//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ecc

public data class ECKeyPair(
  val publicKey: ECPublicKey,
  val privateKey: ECPrivateKey,
) {
  public companion object {
    @JvmStatic
    public fun generate(): ECKeyPair {
      var privateKey = ECPrivateKey.generate()
      return ECKeyPair(privateKey.getPublicKey(), privateKey)
    }
  }
}
