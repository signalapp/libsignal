//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.backups;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class BackupAuthCredential extends ByteArray {

  public BackupAuthCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.BackupAuthCredential_CheckValidContents(contents));
  }

  public BackupAuthCredentialPresentation present(GenericServerPublicParams serverParams) {
    return present(serverParams, new SecureRandom());
  }

  public BackupAuthCredentialPresentation present(
      GenericServerPublicParams serverParams, SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    final byte[] newContents =
        filterExceptions(
            () ->
                Native.BackupAuthCredential_PresentDeterministic(
                    getInternalContentsForJNI(), serverParams.getInternalContentsForJNI(), random));

    try {
      return new BackupAuthCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] getBackupId() {
    return Native.BackupAuthCredential_GetBackupId(getInternalContentsForJNI());
  }

  public BackupLevel getBackupLevel() {
    return BackupLevel.fromValue(
        Native.BackupAuthCredential_GetBackupLevel(getInternalContentsForJNI()));
  }

  public BackupCredentialType getType() {
    return BackupCredentialType.fromValue(
        Native.BackupAuthCredential_GetType(getInternalContentsForJNI()));
  }
}
