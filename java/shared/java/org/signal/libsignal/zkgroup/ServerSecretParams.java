//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.util.Arrays;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class ServerSecretParams extends NativeHandleGuard.SimpleOwner {
  public static ServerSecretParams generate() {
    return generate(new SecureRandom());
  }

  public static ServerSecretParams generate(SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    return new ServerSecretParams(Native.ServerSecretParams_GenerateDeterministic(random));
  }

  public ServerSecretParams(byte[] contents) throws InvalidInputException {
    super(filterExceptions(() -> Native.ServerSecretParams_Deserialize(contents)));
  }

  ServerSecretParams(long nativeHandle) {
    super(nativeHandle);
  }

  public ServerPublicParams getPublicParams() {
    return new ServerPublicParams(this.guardedMap(Native::ServerSecretParams_GetPublicParams));
  }

  public NotarySignature sign(byte[] message) {
    return sign(new SecureRandom(), message);
  }

  public NotarySignature sign(SecureRandom secureRandom, byte[] message) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        this.guardedMap(
            (nativeHandle) ->
                Native.ServerSecretParams_SignDeterministic(nativeHandle, random, message));

    try {
      return new NotarySignature(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  protected void release(long handle) {
    Native.ServerSecretParams_Destroy(handle);
  }

  public byte[] serialize() {
    return guardedMap(Native::ServerSecretParams_Serialize);
  }

  @Override
  public int hashCode() {
    return getClass().hashCode() * 31 + Arrays.hashCode(serialize());
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;

    ServerPublicParams other = (ServerPublicParams) o;
    return ByteArray.constantTimeEqual(this.serialize(), other.serialize());
  }
}
