//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.provisioning

import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.protocol.InvalidMessageException

public object Provisioning {
  /**
   * Encrypts a serialized `ProvisionMessage` or `RegistrationProvisionMessage` to a secondary
   * device, returning a serialized `ProvisionEnvelope`.
   *
   * @param secondaryPublicKey the 33-byte public key from the secondary's provisioning QR code,
   *   i.e. [RecvProvisionCiphertextState.publicKey]
   * @throws IllegalArgumentException if `secondaryPublicKey` is not 33 bytes
   * @throws InvalidMessageException if the first byte of `secondaryPublicKey` is not the X25519 key
   *   type byte (0x05)
   */
  @JvmStatic
  @Throws(InvalidMessageException::class)
  public fun encryptProvisionMessage(
    secondaryPublicKey: ByteArray,
    provisionMessage: ByteArray,
  ): ByteArray = NativeNice.Provisioning_EncryptProvisionMessage(secondaryPublicKey, provisionMessage)
}
