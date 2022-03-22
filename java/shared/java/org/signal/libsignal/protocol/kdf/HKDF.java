/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.signal.libsignal.protocol.kdf;

import org.signal.libsignal.internal.Native;

public abstract class HKDF {
  public static byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength) {
    return Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, null);
  }

  public static byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
    return Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, salt);
  }
}
