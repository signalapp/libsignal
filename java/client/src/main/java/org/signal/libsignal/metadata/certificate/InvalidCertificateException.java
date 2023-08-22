//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate;

public class InvalidCertificateException extends Exception {
  public InvalidCertificateException(String s) {
    super(s);
  }

  public InvalidCertificateException(Exception e) {
    super(e);
  }
}
