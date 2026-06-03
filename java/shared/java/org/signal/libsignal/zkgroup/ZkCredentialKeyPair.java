//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/**
 * A long-term Ristretto ZK credential key pair owned by an account.
 *
 * <p>Distinct from the account's curve25519 identity key. Used as a binding identity across ZK
 * credentials issued to the account (currently the avatar upload credential).
 *
 * <p>The secret half must be persisted by the account holder and synced to linked devices. The
 * public half is uploaded to the server.
 */
public final class ZkCredentialKeyPair extends ByteArray {

  public static ZkCredentialKeyPair generate() {
    return generate(new SecureRandom());
  }

  public static ZkCredentialKeyPair generate(SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ZkCredentialKeyPair_GenerateDeterministic(random);

    try {
      return new ZkCredentialKeyPair(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ZkCredentialKeyPair(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class, () -> Native.ZkCredentialKeyPair_CheckValidContents(contents));
  }

  public ZkCredentialPublicKey getPublicKey() {
    byte[] newContents = Native.ZkCredentialKeyPair_GetPublicKey(contents);
    try {
      return new ZkCredentialPublicKey(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
