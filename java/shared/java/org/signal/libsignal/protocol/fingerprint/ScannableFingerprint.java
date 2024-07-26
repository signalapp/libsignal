//
// Copyright 2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.fingerprint;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;

public class ScannableFingerprint {
  private final byte[] encodedFingerprint;

  ScannableFingerprint(byte[] encodedFingerprint) {
    this.encodedFingerprint = encodedFingerprint;
  }

  /**
   * @return A byte string to be displayed in a QR code.
   */
  public byte[] getSerialized() {
    return this.encodedFingerprint;
  }

  /**
   * Native.ScannableFingerprint_Compare a scanned QR code with what we expect.
   *
   * @param scannedFingerprintData The scanned data
   * @return True if matching, otherwise false.
   * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
   */
  public boolean compareTo(byte[] scannedFingerprintData)
      throws FingerprintVersionMismatchException, FingerprintParsingException {
    return filterExceptions(
        FingerprintVersionMismatchException.class,
        FingerprintParsingException.class,
        () -> Native.ScannableFingerprint_Compare(this.encodedFingerprint, scannedFingerprintData));
  }
}
