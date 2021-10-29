//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

package org.signal.zkgroup;

import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;

public abstract class SecureRandomTest {

  public static SecureRandom createSecureRandom(final byte[] nextRandom) {
    SecureRandom mockRandom = Mockito.mock(SecureRandom.class);
    doAnswer(new Answer() {
      byte[] bytes = Arrays.copyOf(nextRandom, nextRandom.length);

      @Override
      public Object answer(InvocationOnMock invocation) {
        assertNotNull("Bytes have been used", bytes);
        byte[] input = (byte[]) invocation.getArguments()[0];
        assertEquals("setSecureRandomNextBytes was setup with wrong number of bytes", nextRandom.length, input.length);
        System.arraycopy(bytes, 0, input, 0, bytes.length);
        bytes = null;

        return null; // Void method
      }
    }).when(mockRandom).nextBytes(any(byte[].class));

    return mockRandom;
  }
}
