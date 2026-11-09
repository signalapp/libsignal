//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class IdentityKeyTest {
  @Test
  public void testSignAlternateKey() {
    IdentityKeyPair primary = IdentityKeyPair.generate();
    IdentityKeyPair secondary = IdentityKeyPair.generate();
    byte[] signature = secondary.signAlternateIdentity(primary.getPublicKey());
    assertTrue(secondary.getPublicKey().verifyAlternateIdentity(primary.getPublicKey(), signature));
  }

  @Test
  public void testDeserializeWithOffsetAndLength() throws InvalidKeyException {
    IdentityKey key = IdentityKeyPair.generate().getPublicKey();
    byte[] serialized = key.serialize();
    byte[] withPrefix = new byte[serialized.length + 1];
    System.arraycopy(serialized, 0, withPrefix, 1, serialized.length);

    assertEquals(key, new IdentityKey(withPrefix, 1, serialized.length));
    assertThrows(
        IllegalArgumentException.class, () -> new IdentityKey(withPrefix, 1, withPrefix.length));
    assertThrows(
        IllegalArgumentException.class,
        () -> new IdentityKey(withPrefix, withPrefix.length + 1, 0));
  }
}
