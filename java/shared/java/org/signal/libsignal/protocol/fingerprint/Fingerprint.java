/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.fingerprint;

public class Fingerprint {

  private final DisplayableFingerprint displayableFingerprint;
  private final ScannableFingerprint   scannableFingerprint;

  public Fingerprint(DisplayableFingerprint displayableFingerprint,
                     ScannableFingerprint scannableFingerprint)
  {
    this.displayableFingerprint = displayableFingerprint;
    this.scannableFingerprint   = scannableFingerprint;
  }

  /**
   * @return A text fingerprint that can be displayed and compared remotely.
   */
  public DisplayableFingerprint getDisplayableFingerprint() {
    return displayableFingerprint;
  }

  /**
   * @return A scannable fingerprint that can be scanned and compared locally.
   */
  public ScannableFingerprint getScannableFingerprint() {
    return scannableFingerprint;
  }
}
