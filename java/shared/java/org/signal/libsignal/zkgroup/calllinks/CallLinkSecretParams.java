//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

import java.util.UUID;

public final class CallLinkSecretParams extends ByteArray {

  public static CallLinkSecretParams deriveFromRootKey(byte[] rootKey) {
    byte[] newContents = Native.CallLinkSecretParams_DeriveFromRootKey(rootKey);

    try {
      return new CallLinkSecretParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    } 
  }

  public CallLinkSecretParams(byte[] contents) throws InvalidInputException  {
    super(contents);
    Native.CallLinkSecretParams_CheckValidContents(contents);
  }

  public CallLinkPublicParams getPublicParams() {
    byte[] newContents = Native.CallLinkSecretParams_GetPublicParams(contents);

    try {
      return new CallLinkPublicParams(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public UUID decryptUserId(UuidCiphertext ciphertext) throws VerificationFailedException {
    return Native.CallLinkSecretParams_DecryptUserId(getInternalContentsForJNI(), ciphertext.getInternalContentsForJNI());
  }

}
