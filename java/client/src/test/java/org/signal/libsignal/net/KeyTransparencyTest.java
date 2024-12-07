//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.util.Optional;
import java.util.UUID;
import org.junit.Test;
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
  static final String TEST_E164 = "+18005550100";
  static final byte[] TEST_USERNAME_HASH =
      Hex.fromStringCondensedAssert(
          "d237a4b83b463ca7da58d4a16bf6a3ba104506eb412b235eb603ea10f467c655");
  static final byte[] TEST_UNIDENTIFIED_ACCESS_KEY =
      Hex.fromStringCondensedAssert("fdc7951d1507268daf1834b74d23b76c");

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
  public void canBridgeSearchResult() throws Exception {
    SearchResult result = new SearchResult(NativeTesting.TESTING_ChatSearchResult());
    assertEquals(TEST_ACI_IDENTITY_KEY, result.getAciIdentityKey());
    assertEquals(Optional.of(TEST_ACI), result.getAciForE164());
    assertEquals(Optional.of(TEST_ACI), result.getAciForUsernameHash());
    TestStore store = new TestStore();
    store.applyUpdates(TEST_ACI, result);

    assertTrue(store.getAccountData(TEST_ACI).isPresent());
  }
}
