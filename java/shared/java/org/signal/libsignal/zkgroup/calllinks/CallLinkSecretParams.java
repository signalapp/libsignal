//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.calllinks;

import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.groups.UuidCiphertext;
import org.signal.libsignal.zkgroup.internal.ByteArray;
import org.signal.libsignal.internal.Native;

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

  public Aci decryptUserId(UuidCiphertext ciphertext) throws VerificationFailedException {
    try {
      return Aci.parseFromFixedWidthBinary(Native.CallLinkSecretParams_DecryptUserId(getInternalContentsForJNI(), ciphertext.getInternalContentsForJNI()));
    } catch (ServiceId.InvalidServiceIdException e) {
      throw new VerificationFailedException();
    }
  }

}
