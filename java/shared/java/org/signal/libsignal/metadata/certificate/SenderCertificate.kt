//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ecc.ECPublicKey
import java.util.Optional

public class SenderCertificate : NativeHandleGuard.SimpleOwner {
  protected override fun release(nativeHandle: Long) {
    Native.SenderCertificate_Destroy(nativeHandle)
  }

  @Throws(InvalidCertificateException::class)
  public constructor(serialized: ByteArray) : super(createNativeFrom(serialized))

  public constructor(nativeHandle: Long) : super(nativeHandle)

  public val signer: ServerCertificate
    get() = ServerCertificate(guardedMapChecked(Native::SenderCertificate_GetServerCertificate))

  public val key: ECPublicKey
    get() = ECPublicKey(guardedMapChecked(Native::SenderCertificate_GetKey))

  public val senderDeviceId: Int
    get() = guardedMapChecked(Native::SenderCertificate_GetDeviceId)

  public val senderUuid: String
    get() = guardedMapChecked(Native::SenderCertificate_GetSenderUuid)

  public val senderE164: Optional<String>
    get() = Optional.ofNullable(guardedMapChecked(Native::SenderCertificate_GetSenderE164))

  public val sender: String
    get() = this.senderUuid

  /**
   * Returns an ACI if the sender is a valid UUID, `null` otherwise.
   *
   * In a future release SenderCertificate will *only* support ACIs.
   */
  public val senderAci: ServiceId.Aci?
    get() {
      try {
        return ServiceId.Aci.parseFromString(sender)
      } catch (e: ServiceId.InvalidServiceIdException) {
        return null
      }
    }

  public val expiration: Long
    get() = guardedMapChecked(Native::SenderCertificate_GetExpiration)

  public val serialized: ByteArray
    get() = guardedMapChecked(Native::SenderCertificate_GetSerialized)

  public val certificate: ByteArray
    get() = guardedMapChecked(Native::SenderCertificate_GetCertificate)

  public val signature: ByteArray
    get() = guardedMapChecked(Native::SenderCertificate_GetSignature)
}

@Throws(InvalidCertificateException::class)
private fun createNativeFrom(serialized: ByteArray): Long {
  try {
    return Native.SenderCertificate_Deserialize(serialized)
  } catch (e: Exception) {
    throw InvalidCertificateException(e)
  }
}
