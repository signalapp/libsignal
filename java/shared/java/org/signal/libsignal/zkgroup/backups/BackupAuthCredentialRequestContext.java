//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.backups;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import java.util.UUID;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class BackupAuthCredentialRequestContext extends ByteArray {

  public BackupAuthCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.BackupAuthCredentialRequestContext_CheckValidContents(contents));
  }

  public static BackupAuthCredentialRequestContext create(final byte[] backupKey, final UUID aci) {
    final byte[] newContents = Native.BackupAuthCredentialRequestContext_New(backupKey, aci);

    try {
      return new BackupAuthCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public BackupAuthCredentialRequest getRequest() {
    final byte[] newContents = Native.BackupAuthCredentialRequestContext_GetRequest(contents);

    try {
      return new BackupAuthCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public BackupAuthCredential receiveResponse(
      BackupAuthCredentialResponse response, Instant timestamp, GenericServerPublicParams params)
      throws VerificationFailedException {
    final byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                Native.BackupAuthCredentialRequestContext_ReceiveResponse(
                    getInternalContentsForJNI(),
                    response.getInternalContentsForJNI(),
                    timestamp.getEpochSecond(),
                    params.getInternalContentsForJNI()));

    try {
      return new BackupAuthCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
