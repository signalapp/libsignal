//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import java.security.SecureRandom;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public final class GenericServerSecretParams extends ByteArray {

  public static GenericServerSecretParams generate() {
    return generate(new SecureRandom());
  }

  public static GenericServerSecretParams generate(SecureRandom secureRandom) {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents = Native.GenericServerSecretParams_GenerateDeterministic(random);

    try {
      return new GenericServerSecretParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    } 
  }

  public GenericServerSecretParams(byte[] contents) throws InvalidInputException  {
    super(contents);
    Native.GenericServerSecretParams_CheckValidContents(contents);
  }

  public GenericServerPublicParams getPublicParams() {
    byte[] newContents = Native.GenericServerSecretParams_GetPublicParams(contents);
    try {
      return new GenericServerPublicParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    } 
  }

}
