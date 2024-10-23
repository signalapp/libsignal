//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.backups;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class BackupAuthCredentialPresentation extends ByteArray {

  public BackupAuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.BackupAuthCredentialPresentation_CheckValidContents(contents));
  }

  public void verify(GenericServerSecretParams serverParams) throws VerificationFailedException {
    verify(Instant.now(), serverParams);
  }

  public void verify(Instant currentTime, GenericServerSecretParams serverParams)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.BackupAuthCredentialPresentation_Verify(
                getInternalContentsForJNI(),
                currentTime.getEpochSecond(),
                serverParams.getInternalContentsForJNI()));
  }

  public byte[] getBackupId() {
    return Native.BackupAuthCredentialPresentation_GetBackupId(getInternalContentsForJNI());
  }

  public BackupLevel getBackupLevel() {
    return BackupLevel.fromValue(
        Native.BackupAuthCredentialPresentation_GetBackupLevel(getInternalContentsForJNI()));
  }

  public BackupCredentialType getType() {
    return BackupCredentialType.fromValue(
        Native.BackupAuthCredentialPresentation_GetType(getInternalContentsForJNI()));
  }
}
