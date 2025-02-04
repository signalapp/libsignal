//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal;

import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeTesting;

/**
 * Tests that check that libsignal is loadable and available.
 *
 * <p>This test is expected to run in the production configuration, where only {@code
 * libsignal_jni.so} is available (as opposed to the test/debug configuration, which also includes
 * {@code libsignal_jni_testing.so}). The difference is important, since when both are available,
 * {@code libsignal_jni_testing.so} is loaded, with <code>libsignal_jni.so</code> as a fallback.
 * {@code libsignal_jni_testing.so} exposes a superset of the <code>
 * libsignal_jni.so</code> API, including some test only functions, but the actual production
 * configuration only loads {@code libsignal_jni.so}. These tests check that the custom loading code
 * works correctly in production configurations in addition to the test/debug configuration.
 */
public class SmokeTest {
  @Test
  public void testCanCallNativeMethod() {
    Native.keepAlive(null);
  }

  @Test
  public void testCantCallNativeTestingMethod() {
    assertThrows(UnsatisfiedLinkError.class, () -> NativeTesting.test_only_fn_returns_123());
  }
}
