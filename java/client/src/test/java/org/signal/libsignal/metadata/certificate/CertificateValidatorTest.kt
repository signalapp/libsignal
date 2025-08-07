//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate

import org.signal.libsignal.protocol.ecc.ECPublicKey

class CertificateValidatorTest {
  // This is the compile-time test. Android relies on this class being inheritable for tests.
  class CertificateValidatorNeedsToBeinheritable(
    trustRoot: ECPublicKey,
  ) : CertificateValidator(trustRoot)
}
