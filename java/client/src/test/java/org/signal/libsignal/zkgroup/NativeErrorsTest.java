//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import org.junit.Test;
import junit.framework.TestCase;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.zkgroup.internal.*;

public final class NativeErrorsTest extends TestCase {

  @Test
  public void testBadNativeCalls() {
    byte[] params = new byte[10]; // invalid size
    byte[] uuidCiphertext = new byte[65]; // valid size
    boolean failed = false;
    try {
        Native.GroupSecretParams_DecryptServiceId(params, uuidCiphertext);
        failed = true;
    } catch (AssertionError e) {}
    if (failed) {
        throw new AssertionError("Deserialization failure should Assert if CheckValidContents should have caught this");
    }

    byte[] temp = new byte[1]; // wrong length
    try {
        Native.ServerSecretParams_GenerateDeterministic(temp);
        throw new AssertionError("Failed to catch wrong byte array length");
    } catch (IllegalArgumentException e) {}
  }

}
