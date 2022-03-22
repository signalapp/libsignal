//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public abstract class SecureRandomTest {

  private static class MockRandomSpi extends SecureRandomSpi {
    private byte[] bytes;

    private MockRandomSpi(byte[] bytes) {
      this.bytes = bytes;
    }

    protected byte[] engineGenerateSeed(int numBytes) {
      throw new AssertionError("should only use nextBytes()");
    }

    protected void engineNextBytes(byte[] outBytes) {
      assertNotNull("Bytes have been used", bytes);
      assertEquals("createSecureRandom was setup with wrong number of bytes", bytes.length, outBytes.length);
      System.arraycopy(bytes, 0, outBytes, 0, bytes.length);
      bytes = null;
    }

    protected void engineSetSeed(byte[] seed) {
      throw new AssertionError("should only use nextBytes()");
    }
  }

  private static class MockRandom extends SecureRandom {
    private MockRandom(byte[] bytes) {
      super(new MockRandomSpi(bytes), new SecureRandom().getProvider());
    }
  }

  public static SecureRandom createSecureRandom(final byte[] nextRandom) {
    return new MockRandom(nextRandom);
  }
}
