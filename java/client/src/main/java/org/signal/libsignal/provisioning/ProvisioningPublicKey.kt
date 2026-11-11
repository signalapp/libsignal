//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.provisioning

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.internal.NativeNice

/**
 * The public key that a secondary device puts in its provisioning QR code, and that the primary
 * encrypts the `ProvisionMessage` or `RegistrationProvisionMessage` to.
 */
public class ProvisioningPublicKey internal constructor(
  nativeHandle: Long,
) : NativeHandleGuard.SimpleOwner(
    NativeHandleGuard.SimpleOwner.throwIfNull(nativeHandle),
  ) {
  /**
   * Wraps a serialized public key, i.e. the output of [serialize]. The public key is not validated
   * until it is used.
   */
  public constructor(pubkeyBytes: ByteArray) : this(Native.ProvisioningPublicKey_Deserialize(pubkeyBytes))

  protected override fun release(nativeHandle: Long) {
    Native.ProvisioningPublicKey_Destroy(nativeHandle)
  }

  /** Returns the bytes this public key was created from. */
  public fun serialize(): ByteArray = NativeNice.ProvisioningPublicKey_Serialize(this)
}
