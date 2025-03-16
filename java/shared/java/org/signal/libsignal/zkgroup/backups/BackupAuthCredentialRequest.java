//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.backups;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

public final class BackupAuthCredentialRequest extends ByteArray {

  public BackupAuthCredentialRequest(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.BackupAuthCredentialRequest_CheckValidContents(contents));
  }

  /**
   * Issues a BackupAuthCredential.
   *
   * @param timestamp Must be a round number of days. Use {@link Instant#truncatedTo} to ensure
   *     this.
   * @param backupLevel The {@link BackupLevel} that this credential is authorized for
   * @param type The type of upload the credential will be used for
   * @param params The params that will be used by the verifying server to verify this credential.
   */
  public BackupAuthCredentialResponse issueCredential(
      Instant timestamp,
      BackupLevel backupLevel,
      BackupCredentialType type,
      GenericServerSecretParams params) {
    return issueCredential(timestamp, backupLevel, type, params, new SecureRandom());
  }

  /**
   * Issues a BackupAuthCredential, using a dedicated source of randomness.
   *
   * <p>This can be used to make tests deterministic. Prefer {@link #issueCredential(Instant,
   * BackupLevel, BackupCredentialType, GenericServerSecretParams)} if the source of randomness
   * doesn't matter.
   *
   * @param timestamp Must be a round number of days. Use {@link Instant#truncatedTo} to ensure
   *     this.
   * @param backupLevel The {@link BackupLevel} that this credential is authorized for
   * @param type The type of upload the credential will be used for
   * @param params The params that will be used by the verifying server to verify this credential.
   * @param secureRandom Used to hide the server's secrets and make the issued credential unique.
   */
  public BackupAuthCredentialResponse issueCredential(
      Instant timestamp,
      BackupLevel backupLevel,
      BackupCredentialType type,
      GenericServerSecretParams params,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.BackupAuthCredentialRequest_IssueDeterministic(
            getInternalContentsForJNI(),
            timestamp.getEpochSecond(),
            backupLevel.getValue(),
            type.getValue(),
            params.getInternalContentsForJNI(),
            random);

    try {
      return new BackupAuthCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
