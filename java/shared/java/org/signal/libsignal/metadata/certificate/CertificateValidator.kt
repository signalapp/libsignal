//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate

import org.signal.libsignal.internal.Native
import org.signal.libsignal.protocol.ecc.ECPublicKey

/**
 * Used by [SealedSessionCipher](org.signal.libsignal.metadata.SealedSessionCipher) to validate
 * sealed sender certificates.
 */
public open class CertificateValidator(
  public val trustRoots: List<ECPublicKey>,
) {
  public constructor(trustRoot: ECPublicKey) : this(listOf(trustRoot))

  /**
   * Validates `certificate`.
   *
   * The default behavior checks the certificate against each key in [trustRoots] in constant time
   * (that is, no result is produced until every key is checked), making sure **one** of them has
   * signed its embedded server certificate.
   * The `validationTime` parameter is compared numerically against [SenderCertificate.expiration]
   * and is not required to use any specific units, but Signal uses milliseconds since 1970.
   *
   * @throws InvalidCertificateException if the certificate is invalid or has expired
   */
  @Throws(InvalidCertificateException::class)
  public open fun validate(
    certificate: SenderCertificate,
    validationTime: Long,
  ) {
    try {
      certificate.guardedRun { certificateHandle ->
        val trustRootHandles = trustRoots.map { it.unsafeNativeHandleWithoutGuard() }.toLongArray()
        if (!Native.SenderCertificate_Validate(
            certificateHandle,
            trustRootHandles,
            validationTime,
          )
        ) {
          throw InvalidCertificateException("Validation failed")
        }
      }
    } catch (e: InvalidCertificateException) {
      throw e
    } catch (e: Exception) {
      throw InvalidCertificateException(e)
    }
  }

  // VisibleForTesting

  /**
   * Verifies a ServerCertificate against the set of trust roots.
   *
   * This is only meant for convenience in unit testing and thus is *not* a constant-time operation.
   * It is not used by SealedSessionCipher.
   */
  @Throws(InvalidCertificateException::class)
  public fun validate(certificate: ServerCertificate) {
    if (!trustRoots.any { it.verifySignature(certificate.certificate, certificate.signature) }) {
      throw InvalidCertificateException("All signatures failed")
    }
  }
}
