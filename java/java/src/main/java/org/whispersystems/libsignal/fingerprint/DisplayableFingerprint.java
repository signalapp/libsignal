/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.signal.client.internal.Native;
import org.whispersystems.libsignal.util.ByteUtil;

public class DisplayableFingerprint {
  static {
  }


  private String displayString;

  DisplayableFingerprint(byte[] localFingerprint, byte[] remoteFingerprint) {
    this.displayString = Native.DisplayableFingerprint_Format(localFingerprint, remoteFingerprint);
  }

  DisplayableFingerprint(String displayString) {
    this.displayString = displayString;
  }

  public String getDisplayText() {
    return this.displayString;
  }

}
