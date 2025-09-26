//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.keytrans.KeyTransparencyException;
import org.signal.libsignal.keytrans.VerificationFailedException;
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
          "dc711808c2cf66d5e6a33ce41f27d69d942d2e1ff4db22d39b42d2eff8d09746");
  static final byte[] TEST_UNIDENTIFIED_ACCESS_KEY =
      Hex.fromStringCondensedAssert("108d84b71be307bdf101e380a1d7f2a2");

  static {
    try {
      TEST_ACI_IDENTITY_KEY =
          new IdentityKey(
              Hex.fromStringCondensedAssert(
                  "05cdcbb178067f0ddfd258bb21d006e0aa9c7ab132d9fb5e8b027de07d947f9d0c"));
    } catch (InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void canBridgeFatalError() {
    assertThrows(
        VerificationFailedException.class, NativeTesting::TESTING_KeyTransFatalVerificationFailure);
  }

  @Test
  public void canBridgeNonFatalError() {
    var exception =
        assertThrows(
            KeyTransparencyException.class,
            NativeTesting::TESTING_KeyTransNonFatalVerificationFailure);
    // Since VerificationFailedException is a subclass of KeyTransparencyException,
    // it would also satisfy assertThrows.
    assertNotEquals(VerificationFailedException.class, exception.getClass());
  }

  @Test
  public void canBridgeChatSendError() {
    assertThrows(TimeoutException.class, NativeTesting::TESTING_KeyTransChatSendError);
  }
}
