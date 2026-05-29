//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.zkgroup.avatars;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;
import static org.signal.libsignal.zkgroup.internal.Constants.RANDOM_LENGTH;

import java.security.SecureRandom;
import java.time.Instant;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/**
 * A usable avatar upload credential, held by the client after a successful issuance.
 *
 * <p>Call {@link #present} to produce an {@link AvatarUploadCredentialPresentation} for a verifying
 * server.
 */
public final class AvatarUploadCredential extends ByteArray {

  public AvatarUploadCredential(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AvatarUploadCredential_CheckValidContents(contents));
  }

  /** Produces a presentation of this credential for a verifying server. */
  public AvatarUploadCredentialPresentation present(GenericServerPublicParams serverParams) {
    return present(serverParams, new SecureRandom());
  }

  /**
   * Produces a presentation of this credential, using a dedicated source of randomness.
   *
   * <p>This can be used to make tests deterministic. Prefer {@link
   * #present(GenericServerPublicParams)} if the source of randomness doesn't matter.
   */
  public AvatarUploadCredentialPresentation present(
      GenericServerPublicParams serverParams, SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.AvatarUploadCredential_PresentDeterministic(
            getInternalContentsForJNI(), serverParams.getInternalContentsForJNI(), random);

    try {
      return new AvatarUploadCredentialPresentation(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * The 32-byte commitment {@code Cm} (the avatar slot identifier).
   *
   * <p>This is a Pedersen commitment, not a key, so it carries no type-tag prefix.
   */
  public byte[] getCommitment() {
    return Native.AvatarUploadCredential_GetCm(getInternalContentsForJNI());
  }

  /** The redemption time the issuing server chose for this credential. */
  public Instant getRedemptionTime() {
    return Instant.ofEpochSecond(
        Native.AvatarUploadCredential_GetRedemptionTime(getInternalContentsForJNI()));
  }
}
