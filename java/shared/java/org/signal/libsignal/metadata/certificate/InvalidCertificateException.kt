//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate

public class InvalidCertificateException : Exception {
  public constructor(s: String) : super(s)

  public constructor(e: Exception) : super(e)
}
