//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.util.UUID;
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
      Hex.fromStringCondensedAssert("c6f7c258c24d69538ea553b4a943c8d9");

  static {
    try {
      TEST_ACI_IDENTITY_KEY =
          new IdentityKey(
              Hex.fromStringCondensedAssert(
                  "05111f9464c1822c6a2405acf1c5a4366679dc3349fc8eb015c8d7260e3f771177"));
    } catch (InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }
}
