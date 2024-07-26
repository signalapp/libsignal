//
// Copyright 2013-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.kdf;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;

public abstract class HKDF {
  public static byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength) {
    return filterExceptions(
        () -> Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, null));
  }

  public static byte[] deriveSecrets(
      byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
    return filterExceptions(
        () -> Native.HKDF_DeriveSecrets(outputLength, inputKeyMaterial, info, salt));
  }
}
