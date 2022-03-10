//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.zkgroup;

import java.security.SecureRandom;
import org.signal.zkgroup.internal.ByteArray;
import org.signal.client.internal.Native;

import static org.signal.zkgroup.internal.Constants.RANDOM_LENGTH;

public final class ServerSecretParams extends ByteArray {

  public static ServerSecretParams generate() {
    return generate(new SecureRandom());
  }

  public static ServerSecretParams generate(SecureRandom secureRandom) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_GenerateDeterministic(random);

    try {
      return new ServerSecretParams(newContents);
    } catch (IllegalArgumentException e) {
      throw new AssertionError(e);
    } 
  }

  public ServerSecretParams(byte[] contents)  {
    super(contents);
    Native.ServerSecretParams_CheckValidContents(contents);
  }

  public ServerPublicParams getPublicParams() {
    byte[] newContents = Native.ServerSecretParams_GetPublicParams(contents);
    return new ServerPublicParams(newContents);
  }

  public NotarySignature sign(byte[] message) {
    return sign(new SecureRandom(), message);
  }

  public NotarySignature sign(SecureRandom secureRandom, byte[] message) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.ServerSecretParams_SignDeterministic(contents, random, message);

    try {
      return new NotarySignature(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

}
