//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.svr.DataMissingException;
import org.signal.libsignal.svr.RestoreFailedException;
import org.signal.libsignal.svr.SvrException;
import org.signal.libsignal.util.TestEnvironment;

public class Svr3Test {

  private static final String USER_AGENT = "test";

  private final byte[] STORED_SECRET =
      Hex.fromStringCondensedAssert(
          "d2ae1668ac8a2bfd6170498332babad7cd72b9314631559a361310eee0a8adc6");
  private final String TEST_PASSWORD = "password";
  private final String ENCLAVE_SECRET = TestEnvironment.get("LIBSIGNAL_TESTING_ENCLAVE_SECRET");

  record State(EnclaveAuth auth, Network net) {}

  private State state;

  @Before
  public void before() {
    // These tests require access to the SVR3 instances, and will be ignored if the
    // secret is not provided.
    Assume.assumeNotNull(ENCLAVE_SECRET);
    // Generating a random username for each test run to minimize the
    // probability of being throttled
    String username = randomBytesHex(16);
    String otp = Native.CreateOTPFromBase64(username, ENCLAVE_SECRET);
    var auth = new EnclaveAuth(username, otp);
    var net = new Network(Network.Environment.PRODUCTION, USER_AGENT);
    this.state = new State(auth, net);
  }

  @After
  public void after() {
    try {
      this.state.net().svr3().remove(state.auth()).get();
    } catch (Exception ignored) {
    } finally {
      this.state = null;
    }
  }

  static final String randomBytesHex(int size) {
    byte[] bytes = new byte[size];
    SecureRandom r = new SecureRandom();
    r.nextBytes(bytes);
    return Hex.toStringCondensed(bytes);
  }

  @Test
  public void backupAndRestore() throws Exception {
    final int tries = 2;
    Svr3.RestoredSecret restored =
        state
            .net()
            .svr3()
            .backup(STORED_SECRET, TEST_PASSWORD, tries, state.auth())
            .thenCompose(
                shareSet -> state.net().svr3().restore(TEST_PASSWORD, shareSet, state.auth()))
            .get();
    assertEquals(Hex.toStringCondensed(STORED_SECRET), Hex.toStringCondensed(restored.value()));
    assertEquals(tries - 1, restored.triesRemaining());
  }

  @Test
  public void noRestoreAfterRemove() throws Exception {
    final int tries = 10;
    byte[] shareSet =
        state.net().svr3().backup(STORED_SECRET, TEST_PASSWORD, tries, state.auth()).get();
    state.net().svr3().remove(state.auth()).get();
    try {
      // The next attempt should fail
      state.net().svr3().restore(TEST_PASSWORD, shareSet, state.auth()).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof DataMissingException);
    }
  }

  @Test
  public void restoreAfterRotate() throws Exception {
    final int tries = 10;
    byte[] shareSet =
        state.net().svr3().backup(STORED_SECRET, TEST_PASSWORD, tries, state.auth()).get();
    Svr3.RestoredSecret restored =
        state
            .net()
            .svr3()
            .rotate(shareSet, state.auth())
            .thenCompose(
                ignored -> state.net().svr3().restore(TEST_PASSWORD, shareSet, state.auth()))
            .get();
    assertEquals(Hex.toStringCondensed(STORED_SECRET), Hex.toStringCondensed(restored.value()));
    assertEquals(tries - 1, restored.triesRemaining());
  }

  @Test
  public void removeSomethingThatNeverWas() throws Exception {
    state.net().svr3().remove(state.auth()).get();
  }

  @Test
  public void noMoreTries() throws Exception {
    // Backup and first restore should succeed
    byte[] shareSet =
        state.net().svr3().backup(STORED_SECRET, TEST_PASSWORD, 1, state.auth()).get();
    state.net().svr3().restore(TEST_PASSWORD, shareSet, state.auth()).get();
    try {
      // The next attempt should fail
      state.net().svr3().restore(TEST_PASSWORD, shareSet, state.auth()).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof DataMissingException);
    }
  }

  @Test
  public void failedRestore() throws Exception {
    final int tries = 2;
    byte[] shareSet =
        state.net().svr3().backup(STORED_SECRET, TEST_PASSWORD, tries, state.auth()).get();
    try {
      state.net().svr3().restore("wrong password", shareSet, state.auth()).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof RestoreFailedException);
      var restoreFailed = (RestoreFailedException) cause;
      assertEquals(tries - 1, restoreFailed.getTriesRemaining());
    }
  }

  @Test
  public void zeroTries() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> state.net().svr3().backup(STORED_SECRET, TEST_PASSWORD, 0, state.auth()).get());
  }

  @Test
  public void badSecret() throws Exception {
    try {
      state.net().svr3().backup(new byte[31], TEST_PASSWORD, 1, state.auth()).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof AssertionError);
    }
  }

  @Test
  public void badShareSet() throws Exception {
    byte[] shareSet =
        state.net().svr3().backup(STORED_SECRET, TEST_PASSWORD, 1, state.auth()).get();
    shareSet[0] ^= (byte) 0xff;
    try {
      state.net().svr3().restore(TEST_PASSWORD, shareSet, state.auth()).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof SvrException);
    }
  }

  @Test
  public void invalidEnclaveAuth() throws Exception {
    String username = randomBytesHex(16);
    // Intentionally invalid enclave secret
    String otp = Native.CreateOTP(username, new byte[32]);
    var auth = new EnclaveAuth(username, otp);
    try {
      state.net().svr3().backup(STORED_SECRET, TEST_PASSWORD, 10, auth).get();
      fail("Must have thrown");
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertFalse(
          "Unexpectedly generic exception used: " + cause, cause instanceof NetworkException);
      assertTrue("Unexpected exception: " + cause, cause instanceof NetworkProtocolException);
    }
  }

  @Test
  public void restoreAfterMigrate() throws Exception {
    // migrate is equivalent to backup, so this test merely validates that the "write" happens,
    // not that the value is removed from the old location.
    final int tries = 2;
    Svr3.RestoredSecret restored =
        state
            .net()
            .svr3()
            .migrate(STORED_SECRET, TEST_PASSWORD, tries, state.auth())
            .thenCompose(
                shareSet -> state.net().svr3().restore(TEST_PASSWORD, shareSet, state.auth()))
            .get();
    assertEquals(Hex.toStringCondensed(STORED_SECRET), Hex.toStringCondensed(restored.value()));
    assertEquals(tries - 1, restored.triesRemaining());
  }
}
