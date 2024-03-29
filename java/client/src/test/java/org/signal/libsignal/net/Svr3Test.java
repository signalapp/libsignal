//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.svr.DataMissingException;
import org.signal.libsignal.svr.RestoreFailedException;
import org.signal.libsignal.svr.SvrException;

public class Svr3Test {

  private final byte[] STORED_SECRET =
      Hex.fromStringCondensedAssert(
          "d2ae1668ac8a2bfd6170498332babad7cd72b9314631559a361310eee0a8adc6");
  private final String ENCLAVE_SECRET = System.getenv("ENCLAVE_SECRET");

  private EnclaveAuth auth;

  @Before
  public void before() {
    // These tests require access to staging SVR3, and will be ignored if the
    // secret is not provided.
    Assume.assumeNotNull(ENCLAVE_SECRET);
    // Generating a random username for each test run to minimize the
    // probability of being throttled
    String username = randomBytesHex(16);
    String otp = Native.CreateOTPFromBase64(username, ENCLAVE_SECRET);
    this.auth = new EnclaveAuth(username, otp);
  }

  static final String randomBytesHex(int size) {
    byte[] bytes = new byte[size];
    SecureRandom r = new SecureRandom();
    r.nextBytes(bytes);
    return Hex.toStringCondensed(bytes);
  }

  @Test
  public void backupAndRestore() throws Exception {
    Network net = new Network(Network.Environment.STAGING);
    byte[] restored =
        net.svr3()
            .backup(STORED_SECRET, "password", 2, this.auth)
            .thenCompose(shareSet -> net.svr3().restore("password", shareSet, this.auth))
            .get();
    assertEquals(Hex.toStringCondensed(STORED_SECRET), Hex.toStringCondensed(restored));
  }

  @Test
  public void noMoreTries() throws Exception {
    Network net = new Network(Network.Environment.STAGING);
    // Backup and first restore should succeed
    byte[] shareSet = net.svr3().backup(STORED_SECRET, "password", 1, this.auth).get();
    net.svr3().restore("password", shareSet, this.auth).get();
    try {
      // The next attempt should fail
      net.svr3().restore("password", shareSet, this.auth).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof DataMissingException);
    }
  }

  @Test
  public void failedRestore() throws Exception {
    Network net = new Network(Network.Environment.STAGING);
    byte[] shareSet = net.svr3().backup(STORED_SECRET, "password", 1, this.auth).get();
    try {
      net.svr3().restore("wrong password", shareSet, this.auth).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof RestoreFailedException);
    }
  }

  @Test
  public void zeroTries() throws Exception {
    Network net = new Network(Network.Environment.STAGING);
    assertThrows(
        IllegalArgumentException.class,
        () -> net.svr3().backup(STORED_SECRET, "password", 0, this.auth).get());
  }

  @Test
  public void badSecret() throws Exception {
    Network net = new Network(Network.Environment.STAGING);
    try {
      net.svr3().backup(new byte[31], "password", 1, this.auth).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof AssertionError);
    }
  }

  @Test
  public void badShareSet() throws Exception {
    Network net = new Network(Network.Environment.STAGING);
    byte[] shareSet = net.svr3().backup(STORED_SECRET, "password", 1, this.auth).get();
    shareSet[0] ^= 0xff;
    try {
      net.svr3().restore("password", shareSet, this.auth).get();
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      assertTrue("Unexpected exception: " + cause, cause instanceof SvrException);
    }
  }
}
