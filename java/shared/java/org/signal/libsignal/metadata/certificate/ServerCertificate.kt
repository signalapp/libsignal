//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate

import org.signal.libsignal.internal.Native
import org.signal.libsignal.internal.NativeHandleGuard
import org.signal.libsignal.protocol.ServiceId
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
import java.util.Optional

public class ServerCertificate : NativeHandleGuard.SimpleOwner {
  protected override fun release(nativeHandle: Long) {
    Native.ServerCertificate_Destroy(nativeHandle)
  }

  public constructor(nativeHandle: Long) : super(nativeHandle)

  @Throws(InvalidCertificateException::class)
  public constructor(serialized: ByteArray) : super(createNativeFrom(serialized))

  /** Use `trustRoot` to generate and sign a new server certificate containing `key`. */
  public constructor(trustRoot: ECPrivateKey, keyId: Int, key: ECPublicKey) :
    super(
      key.guardedMap { serverPublicHandle ->
        trustRoot.guardedMap { trustRootHandle ->
          Native.ServerCertificate_New(keyId, serverPublicHandle, trustRootHandle)
        }
      },
    )

  public val keyId: Int
    get() = guardedMapChecked(Native::ServerCertificate_GetKeyId)

  public val key: ECPublicKey
    get() = ECPublicKey(guardedMap(Native::ServerCertificate_GetKey))

  public val serialized: ByteArray
    get() = guardedMap(Native::ServerCertificate_GetSerialized)

  public val certificate: ByteArray
    get() = guardedMapChecked(Native::ServerCertificate_GetCertificate)

  public val signature: ByteArray
    get() = guardedMapChecked(Native::ServerCertificate_GetSignature)

  /**
   * Issue a sender certificate.
   *
   * `signingKey` must be the private key that corresponds to [key], or the
   * resulting certificate won't have a valid signature.
   */
  public fun issue(
    signingKey: ECPrivateKey,
    senderUuid: String,
    senderE164: Optional<String>,
    senderDeviceId: Int,
    senderIdentityKey: ECPublicKey,
    expiration: Long,
  ): SenderCertificate =
    senderIdentityKey.guardedMap { identityHandle ->
      this.guardedMap { serverCertificateHandle ->
        signingKey.guardedMap { serverPrivateHandle ->
          SenderCertificate(
            Native.SenderCertificate_New(
              senderUuid,
              senderE164.orElse(null),
              senderDeviceId,
              identityHandle,
              expiration,
              serverCertificateHandle,
              serverPrivateHandle,
            ),
          )
        }
      }
    }

  /**
   * Issue a sender certificate.
   *
   * `signingKey` must be the private key that corresponds to [key], or the
   * resulting certificate won't have a valid signature.
   */
  public fun issue(
    signingKey: ECPrivateKey,
    sender: ServiceId,
    senderE164: Optional<String>,
    senderDeviceId: Int,
    senderIdentityKey: ECPublicKey,
    expiration: Long,
  ): SenderCertificate =
    issue(
      signingKey,
      sender.toString(),
      senderE164,
      senderDeviceId,
      senderIdentityKey,
      expiration,
    )
}

@Throws(InvalidCertificateException::class)
private fun createNativeFrom(serialized: ByteArray): Long {
  try {
    return Native.ServerCertificate_Deserialize(serialized)
  } catch (e: Exception) {
    throw InvalidCertificateException(e)
  }
}
