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
import org.signal.libsignal.zkgroup.GenericServerPublicParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.ZkCredentialKeyPair;
import org.signal.libsignal.zkgroup.internal.ByteArray;

/**
 * Client-side state for an in-flight avatar upload credential request.
 *
 * <p>This value is not sent over the wire; it is retained by the client between issuing a {@link
 * AvatarUploadCredentialRequest} and receiving the corresponding {@link
 * AvatarUploadCredentialResponse}.
 */
public final class AvatarUploadCredentialRequestContext extends ByteArray {

  public AvatarUploadCredentialRequestContext(byte[] contents) throws InvalidInputException {
    super(contents);
    filterExceptions(
        InvalidInputException.class,
        () -> Native.AvatarUploadCredentialRequestContext_CheckValidContents(contents));
  }

  /**
   * Creates a new request context for {@code aci}.
   *
   * @param aci The account the credential will be issued for. The issuing server must independently
   *     authenticate this ACI.
   * @param zkCredentialKeyPair The account's long-term Ristretto ZK credential key pair.
   * @param rotationId The server-chosen avatar slot rotation ID, which the client already received
   *     when it set its ZK credential key. It is folded into the commitment; the issuing server
   *     verifies the request against its own rotation ID, so this must match the server's value.
   */
  public static AvatarUploadCredentialRequestContext create(
      Aci aci, ZkCredentialKeyPair zkCredentialKeyPair, long rotationId) {
    return create(aci, zkCredentialKeyPair, rotationId, new SecureRandom());
  }

  /**
   * Creates a new request context, using a dedicated source of randomness.
   *
   * <p>This can be used to make tests deterministic. Prefer {@link #create(Aci,
   * ZkCredentialKeyPair, long)} if the source of randomness doesn't matter.
   */
  public static AvatarUploadCredentialRequestContext create(
      Aci aci,
      ZkCredentialKeyPair zkCredentialKeyPair,
      long rotationId,
      SecureRandom secureRandom) {
    byte[] random = new byte[RANDOM_LENGTH];
    secureRandom.nextBytes(random);

    byte[] newContents =
        Native.AvatarUploadCredentialRequestContext_New(
            aci.toServiceIdFixedWidthBinary(),
            zkCredentialKeyPair.getInternalContentsForJNI(),
            rotationId,
            random);

    try {
      return new AvatarUploadCredentialRequestContext(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /** The request to send to the issuing server. */
  public AvatarUploadCredentialRequest getRequest() {
    byte[] newContents =
        Native.AvatarUploadCredentialRequestContext_GetRequest(getInternalContentsForJNI());

    try {
      return new AvatarUploadCredentialRequest(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Verifies the issuing server's response using the current system time.
   *
   * <p>Equivalent to {@link #receiveResponse(AvatarUploadCredentialResponse, Instant,
   * GenericServerPublicParams)} called with {@code Instant.now()}.
   *
   * @param response The response received from the issuing server.
   * @param params The public params matching the secret params the issuing server used.
   * @throws VerificationFailedException if the response is not valid for this context.
   */
  public AvatarUploadCredential receiveResponse(
      AvatarUploadCredentialResponse response, GenericServerPublicParams params)
      throws VerificationFailedException {
    return receiveResponse(response, Instant.now(), params);
  }

  /**
   * Verifies the issuing server's response and produces a usable {@link AvatarUploadCredential}.
   *
   * <p>The issuing server chooses the redemption time and embeds it in {@code response}. The client
   * doesn't need to predict it; this call confirms only that the credential is usable at {@code
   * now}, since the verifying server applies the same window (see {@link
   * AvatarUploadCredentialPresentation#verify}).
   *
   * @param response The response received from the issuing server.
   * @param now The client's view of wall-clock time. The response's redemption time must be
   *     day-aligned and within the redemption window relative to this.
   * @param params The public params matching the secret params the issuing server used.
   * @throws VerificationFailedException if the response is not valid for this context.
   */
  public AvatarUploadCredential receiveResponse(
      AvatarUploadCredentialResponse response, Instant now, GenericServerPublicParams params)
      throws VerificationFailedException {
    byte[] newContents =
        filterExceptions(
            VerificationFailedException.class,
            () ->
                Native.AvatarUploadCredentialRequestContext_ReceiveResponse(
                    getInternalContentsForJNI(),
                    response.getInternalContentsForJNI(),
                    now.getEpochSecond(),
                    params.getInternalContentsForJNI()));

    try {
      return new AvatarUploadCredential(newContents);
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }
}
