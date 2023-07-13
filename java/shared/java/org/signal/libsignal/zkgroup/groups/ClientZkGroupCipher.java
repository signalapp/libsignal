//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groups;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.UUID;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;

import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

public class ClientZkGroupCipher {

  private final GroupSecretParams groupSecretParams;

  public ClientZkGroupCipher(GroupSecretParams groupSecretParams) {
    this.groupSecretParams = groupSecretParams;
  }

  public UuidCiphertext encrypt(ServiceId serviceId) {
    byte[] newContents = Native.GroupSecretParams_EncryptServiceId(groupSecretParams.getInternalContentsForJNI(), serviceId.toServiceIdFixedWidthBinary());

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ServiceId decrypt(UuidCiphertext uuidCiphertext) throws VerificationFailedException {
    try {
     return ServiceId.parseFromFixedWidthBinary(Native.GroupSecretParams_DecryptServiceId(groupSecretParams.getInternalContentsForJNI(), uuidCiphertext.getInternalContentsForJNI()));
    } catch (ServiceId.InvalidServiceIdException e) {
      throw new VerificationFailedException();
    }
  }

  public ProfileKeyCiphertext encryptProfileKey(ProfileKey profileKey, ServiceId.Aci userId) {
     byte[] newContents = Native.GroupSecretParams_EncryptProfileKey(groupSecretParams.getInternalContentsForJNI(), profileKey.getInternalContentsForJNI(), userId.toServiceIdFixedWidthBinary());

    try {
      return new ProfileKeyCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKey decryptProfileKey(ProfileKeyCiphertext profileKeyCiphertext, ServiceId.Aci userId) throws VerificationFailedException {
    byte[] newContents = Native.GroupSecretParams_DecryptProfileKey(groupSecretParams.getInternalContentsForJNI(), profileKeyCiphertext.getInternalContentsForJNI(), userId.toServiceIdFixedWidthBinary());

    try {
      return new ProfileKey(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] encryptBlob(byte[] plaintext) throws VerificationFailedException {
    return encryptBlob(new SecureRandom(), plaintext);
  }

  public byte[] encryptBlob(SecureRandom secureRandom, byte[] plaintext) throws VerificationFailedException {
    byte[] random      = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);
    return Native.GroupSecretParams_EncryptBlobWithPaddingDeterministic(groupSecretParams.getInternalContentsForJNI(), random, plaintext, 0);
  }

  public byte[] decryptBlob(byte[] blobCiphertext) throws VerificationFailedException {
    return Native.GroupSecretParams_DecryptBlobWithPadding(groupSecretParams.getInternalContentsForJNI(), blobCiphertext);
  }

}
