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
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.ZkCredentialPublicKey;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/** The request a client sends to the issuing server to obtain an avatar upload credential. */
public final class AvatarUploadCredentialRequest extends ByteArray {

  public AvatarUploadCredentialRequest(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AvatarUploadCredentialRequest_CheckValidContents(contents));
  }

  /**
   * Issues an avatar upload credential.
   *
   * @param aci The account this credential is for. The server must independently authenticate the
   *     client as this ACI.
   * @param zkCredentialKeyPublic The account's long-term Ristretto ZK credential public key from
   *     the server's authoritative store for this account. The request's well-formedness proof
   *     binds the blinded commitment to this key, so passing the wrong value will fail issuance.
   * @param rotationId The server-chosen avatar slot rotation ID, incorporated into the commitment.
   *     The client received this value when it set its ZK credential key.
   * @param redemptionTime Must be a round number of days. Use {@link Instant#truncatedTo} to ensure
   *     this.
   * @param params The params that will be used by the verifying server to verify this credential.
   * @throws VerificationFailedException if the request is not well-formed for {@code aci} and
   *     {@code zkCredentialKeyPublic}.
   */
  public AvatarUploadCredentialResponse issueCredential(
      Aci aci,
      ZkCredentialPublicKey zkCredentialKeyPublic,
      long rotationId,
      Instant redemptionTime,
      GenericServerSecretParams params)
      throws VerificationFailedException {
    return issueCredential(
        aci, zkCredentialKeyPublic, rotationId, redemptionTime, params, new SecureRandom());
  }

  /**
   * Issues an avatar upload credential, using a dedicated source of randomness.
   *
   * <p>This can be used to make tests deterministic. Prefer {@link #issueCredential(Aci,
   * ZkCredentialPublicKey, long, Instant, GenericServerSecretParams)} if the source of randomness
   * doesn't matter.
   */
  public AvatarUploadCredentialResponse issueCredential(
      Aci aci,
      ZkCredentialPublicKey zkCredentialKeyPublic,
      long rotationId,
      Instant redemptionTime,
      GenericServerSecretParams params,
      SecureRandom secureRandom)
      throws VerificationFailedException {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                Native.AvatarUploadCredentialRequest_IssueDeterministic(
                    getInternalContentsForJNI(),
                    aci.toServiceIdFixedWidthBinary(),
                    zkCredentialKeyPublic.getInternalContentsForJNI(),
                    rotationId,
                    redemptionTime.getEpochSecond(),
                    params.getInternalContentsForJNI(),
                    random));

    try {
      return new AvatarUploadCredentialResponse(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
