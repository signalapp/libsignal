//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.whispersystems.libsignal;

import junit.framework.TestCase;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;

public class IdentityKeyTest extends TestCase {
  public void testSignAlternateKey() {
    IdentityKeyPair primary = IdentityKeyPair.generate();
    IdentityKeyPair secondary = IdentityKeyPair.generate();
    byte[] signature = secondary.signAlternateIdentity(primary.getPublicKey());
    assertTrue(secondary.getPublicKey().verifyAlternateIdentity(primary.getPublicKey(), signature));
  }
}
