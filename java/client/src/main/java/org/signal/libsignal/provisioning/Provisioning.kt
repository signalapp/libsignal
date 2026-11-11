//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.provisioning

import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.protocol.InvalidKeyException

public object Provisioning {
  /**
   * Encrypts a serialized `ProvisionMessage` or `RegistrationProvisionMessage` to a secondary
   * device, returning a serialized `ProvisionEnvelope`.
   *
   * @param secondaryPublicKey the public key from the secondary's provisioning QR code, i.e.
   *   [RecvProvisionCiphertextState.publicKey]
   * @throws InvalidKeyException if `secondaryPublicKey` is malformed
   */
  @JvmStatic
  @Throws(InvalidKeyException::class)
  public fun encryptProvisionMessage(
    secondaryPublicKey: ProvisioningPublicKey,
    provisionMessage: ByteArray,
  ): ByteArray = NativeNice.Provisioning_EncryptProvisionMessage(secondaryPublicKey, provisionMessage)
}
