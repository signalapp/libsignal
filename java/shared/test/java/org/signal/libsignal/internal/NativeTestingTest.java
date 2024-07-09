//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import org.junit.Test;

public class NativeTestingTest {
  @Test
  public void canCallNativeTestingFns() throws Exception {
    int result = NativeTesting.test_only_fn_returns_123();
    assertEquals(123, result);
  }
}
