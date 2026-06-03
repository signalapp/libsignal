//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.hsmenclave;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class HsmEnclaveClientTest {
  @Test
  public void testCreateClient() throws Exception {
    byte[] validKey = new byte[32];
    List<byte[]> hashes = new ArrayList<>();
    hashes.add(
        new byte[] {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0
        });
    hashes.add(
        new byte[] {
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1
        });
    HsmEnclaveClient hsmEnclaveClient = new HsmEnclaveClient(validKey, hashes);
    byte[] initialMessage = hsmEnclaveClient.initialRequest();
    assertEquals(112, initialMessage.length);
  }

  @Test
  public void testCreateClientFailsWithInvalidPublicKey() {
    byte[] invalidKey = new byte[31];
    List<byte[]> hashes = new ArrayList<>();
    hashes.add(
        new byte[] {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0
        });
    hashes.add(
        new byte[] {
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1
        });
    try {
      new HsmEnclaveClient(invalidKey, hashes);
    } catch (IllegalArgumentException e) {
      return;
    }
    fail();
  }

  @Test
  public void testCreateClientFailsWithInvalidHash() {
    byte[] validKey = new byte[32];
    List<byte[]> hashes = new ArrayList<>();
    hashes.add(
        new byte[] {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        });
    hashes.add(
        new byte[] {
          1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
          1, 1, 0, 0, 0, 0
        });
    try {
      new HsmEnclaveClient(validKey, hashes);
    } catch (IllegalArgumentException e) {
      return;
    }
    fail();
  }

  @Test
  public void testCreateClientFailsWithNoHashes() {
    byte[] validKey = new byte[32];
    List<byte[]> hashes = new ArrayList<>();
    try {
      new HsmEnclaveClient(validKey, hashes);
    } catch (IllegalArgumentException e) {
      return;
    }
    fail();
  }

  @Test
  public void testEstablishedSendFailsPriorToEstablishment() throws Exception {
    byte[] validKey = new byte[32];
    List<byte[]> hashes = new ArrayList<>();
    hashes.add(
        new byte[] {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0
        });
    HsmEnclaveClient hsmEnclaveClient = new HsmEnclaveClient(validKey, hashes);
    try {
      hsmEnclaveClient.establishedSend(new byte[] {1, 2, 3});
    } catch (IllegalStateException e) {
      return;
    }
    fail();
  }

  @Test
  public void testEstablishedRecvFailsPriorToEstablishment() throws Exception {
    byte[] validKey = new byte[32];
    List<byte[]> hashes = new ArrayList<>();
    hashes.add(
        new byte[] {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0
        });
    HsmEnclaveClient hsmEnclaveClient = new HsmEnclaveClient(validKey, hashes);
    try {
      hsmEnclaveClient.establishedRecv(new byte[] {1, 2, 3});
    } catch (IllegalStateException e) {
      return;
    }
    fail();
  }
}
