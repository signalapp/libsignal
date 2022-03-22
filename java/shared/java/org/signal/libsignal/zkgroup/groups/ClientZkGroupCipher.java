//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.groups;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.UUID;
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

  public UuidCiphertext encryptUuid(UUID uuid) {
    byte[] newContents = Native.GroupSecretParams_EncryptUuid(groupSecretParams.getInternalContentsForJNI(), uuid);

    try {
      return new UuidCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public UUID decryptUuid(UuidCiphertext uuidCiphertext) throws VerificationFailedException {
     return Native.GroupSecretParams_DecryptUuid(groupSecretParams.getInternalContentsForJNI(), uuidCiphertext.getInternalContentsForJNI());
  }

  public ProfileKeyCiphertext encryptProfileKey(ProfileKey profileKey, UUID uuid) {
     byte[] newContents = Native.GroupSecretParams_EncryptProfileKey(groupSecretParams.getInternalContentsForJNI(), profileKey.getInternalContentsForJNI(), uuid);

    try {
      return new ProfileKeyCiphertext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ProfileKey decryptProfileKey(ProfileKeyCiphertext profileKeyCiphertext, UUID uuid) throws VerificationFailedException {
    byte[] newContents = Native.GroupSecretParams_DecryptProfileKey(groupSecretParams.getInternalContentsForJNI(), profileKeyCiphertext.getInternalContentsForJNI(), uuid);

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
