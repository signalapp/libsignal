//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.avatars;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/** A presentation of an {@link AvatarUploadCredential}, sent to a verifying server. */
public final class AvatarUploadCredentialPresentation extends ByteArray {

  public AvatarUploadCredentialPresentation(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AvatarUploadCredentialPresentation_CheckValidContents(contents));
  }

  /** Verifies the presentation against the current time. */
  public void verify(GenericServerSecretParams serverParams) throws VerificationFailedException {
    verify(Instant.now(), serverParams);
  }

  /**
   * Verifies the presentation against {@code currentTime}.
   *
   * @throws VerificationFailedException if the presentation is invalid or outside its redemption
   *     window.
   */
  public void verify(Instant currentTime, GenericServerSecretParams serverParams)
      throws VerificationFailedException {
    filterExceptions(
        VerificationFailedException.class,
        () ->
            Native.AvatarUploadCredentialPresentation_Verify(
                getInternalContentsForJNI(),
                currentTime.getEpochSecond(),
                serverParams.getInternalContentsForJNI()));
  }

  /**
   * The 32-byte commitment {@code Cm} (the avatar slot identifier) revealed by this presentation.
   *
   * <p>This is a Pedersen commitment, not a key, so it carries no type-tag prefix.
   */
  public byte[] getCommitment() {
    return Native.AvatarUploadCredentialPresentation_GetCm(getInternalContentsForJNI());
  }

  /** The redemption time the credential was issued for. */
  public Instant getRedemptionTime() {
    return Instant.ofEpochSecond(
        Native.AvatarUploadCredentialPresentation_GetRedemptionTime(getInternalContentsForJNI()));
  }
}
