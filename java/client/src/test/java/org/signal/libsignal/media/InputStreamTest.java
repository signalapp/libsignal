//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import org.junit.Test;
import org.signal.libsignal.internal.Native;

public class InputStreamTest {

  @Test
  public void testReadIntoEmptyBuffer() {
    byte[] data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes();
    assertArrayEquals(
        Native.TESTING_InputStreamReadIntoZeroLengthSlice(new ByteArrayInputStream(data)), data);
  }
}
