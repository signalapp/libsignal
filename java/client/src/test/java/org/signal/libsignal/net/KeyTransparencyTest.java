//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;
import static org.signal.libsignal.net.KeyTransparency.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.keytrans.SearchResult;
import org.signal.libsignal.keytrans.TestStore;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.util.Hex;

public class KeyTransparencyTest {
  static final ServiceId.Aci TEST_ACI =
      new ServiceId.Aci(UUID.fromString("90c979fd-eab4-4a08-b6da-69dedeab9b29"));
  static final IdentityKey TEST_ACI_IDENTITY_KEY;

  static {
    try {
      TEST_ACI_IDENTITY_KEY =
          new IdentityKey(
              Hex.fromStringCondensedAssert(
                  "05d0e797ec91a4bce0e88959c419e96eb4fdabbb3dc688965584c966dc24195609"));
    } catch (InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void validAciSearchKey() throws Exception {
    byte[] actual = searchKeyForAci(TEST_ACI);

    assertEquals(17, actual.length);
    assertEquals((byte) 'a', actual[0]);
    assertEquals(
        Hex.toStringCondensed(TEST_ACI.toServiceIdBinary()),
        Hex.toStringCondensed(Arrays.copyOfRange(actual, 1, actual.length)));
  }

  @Test
  public void invalidAciSearchKey() throws Exception {
    assertThrows(
        IllegalArgumentException.class, () -> Native.KeyTransparency_AciSearchKey(new byte[42]));
  }

  @Test
  public void nullAciSearchKey() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> Native.KeyTransparency_AciSearchKey(null));
  }

  @Test
  public void validE164SearchKey() throws Exception {
    assertArrayEquals(
        "n+18005550100".getBytes(StandardCharsets.UTF_8), searchKeyForE164("+18005550100"));
  }

  @Test
  public void validUsernameHashSearchKey() throws Exception {
    assertArrayEquals(
        new byte[] {(byte) 'u', 1, 2, 3}, searchKeyForUsernameHash(new byte[] {1, 2, 3}));
  }

  @Test
  public void canBridgeSearchResult() throws Exception {
    SearchResult result = new SearchResult(NativeTesting.TESTING_ChatSearchResult());
    assertEquals(TEST_ACI_IDENTITY_KEY, result.getAciIdentityKey());
    assertEquals(Optional.of(TEST_ACI), result.getAciForE164());
    assertEquals(Optional.of(TEST_ACI), result.getAciForUsernameHash());
    TestStore store = new TestStore();
    store.applyUpdates(result);

    assertNotNull(store.lastTreeHead);
    assertTrue(store.getMonitorData(searchKeyForAci(TEST_ACI)).isPresent());
  }
}
