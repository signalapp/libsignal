//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.provisioning

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.protocol.InvalidMessageException

/**
 * The state that a secondary device keeps while it is waiting to receive an encrypted `ProvisionMessage` or
 * `RegistrationProvisionMessage` from the primary.
 */
public class RecvProvisionCiphertextState internal constructor(
  nativeHandle: Long,
) : NativeHandleGuard.SimpleOwner(
    NativeHandleGuard.SimpleOwner.throwIfNull(nativeHandle),
  ) {
  public companion object {
    /** Generates a new state with a fresh, random keypair. */
    @JvmStatic
    public fun generate(): RecvProvisionCiphertextState = NativeNice.RecvProvisionCiphertextState_Generate()
  }

  protected override fun release(nativeHandle: Long) {
    Native.RecvProvisionCiphertextState_Destroy(nativeHandle)
  }

  /**
   * The public key that the primary should encrypt to. This is what the secondary puts in its
   * provisioning QR code.
   */
  public val publicKey: ProvisioningPublicKey
    get() = NativeNice.RecvProvisionCiphertextState_GetPublicKey(this)

  /**
   * Decrypts a serialized `ProvisionEnvelope` and returns the underlying serialized
   * `ProvisionMessage` or `RegistrationProvisionMessage`.
   *
   * @throws InvalidMessageException if the envelope is malformed, was not encrypted to this state's
   *   public key, or has been tampered with
   */
  @Throws(InvalidMessageException::class)
  public fun decryptEnvelope(envelope: ByteArray): ByteArray =
    NativeNice.RecvProvisionCiphertextState_DecryptEnvelope(this, envelope)
}
