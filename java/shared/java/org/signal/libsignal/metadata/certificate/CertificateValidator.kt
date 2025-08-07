//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate

import org.signal.libsignal.internal.Native
import org.signal.libsignal.protocol.ecc.ECPublicKey

public open class CertificateValidator(
  public val trustRoot: ECPublicKey,
) {
  @Throws(InvalidCertificateException::class)
  public fun validate(
    certificate: SenderCertificate,
    validationTime: Long,
  ) {
    try {
      certificate.guardedRun { certificateHandle ->
        trustRoot.guardedRun { trustRootHandle ->
          if (!Native.SenderCertificate_Validate(
              certificateHandle,
              trustRootHandle,
              validationTime,
            )
          ) {
            throw InvalidCertificateException("Validation failed")
          }
        }
      }
    } catch (e: Exception) {
      throw InvalidCertificateException(e)
    }
  }

  // VisibleForTesting
  @Throws(InvalidCertificateException::class)
  public fun validate(certificate: ServerCertificate) {
    if (!trustRoot.verifySignature(certificate.certificate, certificate.signature)) {
      throw InvalidCertificateException("Signature failed")
    }
  }
}
