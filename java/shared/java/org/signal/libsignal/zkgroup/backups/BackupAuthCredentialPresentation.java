//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.backups;

import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class BackupAuthCredentialPresentation extends ByteArray {

  public BackupAuthCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    Native.BackupAuthCredentialPresentation_CheckValidContents(contents);
  }

  public void verify(GenericServerSecretParams serverParams) throws VerificationFailedException {
    verify(Instant.now(), serverParams);
  }

  public void verify(Instant currentTime, GenericServerSecretParams serverParams)
      throws VerificationFailedException {
    Native.BackupAuthCredentialPresentation_Verify(
        getInternalContentsForJNI(),
        currentTime.getEpochSecond(),
        serverParams.getInternalContentsForJNI());
  }

  public byte[] getBackupId() {
    return Native.BackupAuthCredentialPresentation_GetBackupId(getInternalContentsForJNI());
  }

  public long getReceiptLevel() {
    return Native.BackupAuthCredentialPresentation_GetReceiptLevel(getInternalContentsForJNI());
  }
}
