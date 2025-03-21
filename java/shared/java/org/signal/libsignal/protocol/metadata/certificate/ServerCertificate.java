//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.certificate;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.Optional;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class ServerCertificate extends NativeHandleGuard.SimpleOwner {
  @Override
  protected void release(long nativeHandle) {
    Native.ServerCertificate_Destroy(nativeHandle);
  }

  public ServerCertificate(long nativeHandle) {
    super(nativeHandle);
  }

  public ServerCertificate(byte[] serialized) throws InvalidCertificateException {
    super(ServerCertificate.createNativeFrom(serialized));
  }

  private static long createNativeFrom(byte[] serialized) throws InvalidCertificateException {
    try {
      return Native.ServerCertificate_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  /** Use {@code trustRoot} to generate and sign a new server certificate containing {@code key}. */
  public ServerCertificate(ECPrivateKey trustRoot, int keyId, ECPublicKey key) {
    super(
        filterExceptions(
            () ->
                key.guardedMapChecked(
                    (serverPublicHandle) ->
                        trustRoot.guardedMapChecked(
                            (trustRootHandle) ->
                                Native.ServerCertificate_New(
                                    keyId, serverPublicHandle, trustRootHandle)))));
  }

  public int getKeyId() {
    return filterExceptions(() -> guardedMapChecked(Native::ServerCertificate_GetKeyId));
  }

  public ECPublicKey getKey() {
    return new ECPublicKey(
        filterExceptions(() -> guardedMapChecked(Native::ServerCertificate_GetKey)));
  }

  public byte[] getSerialized() {
    return filterExceptions(() -> guardedMapChecked(Native::ServerCertificate_GetSerialized));
  }

  public byte[] getCertificate() {
    return filterExceptions(() -> guardedMapChecked(Native::ServerCertificate_GetCertificate));
  }

  public byte[] getSignature() {
    return filterExceptions(() -> guardedMapChecked(Native::ServerCertificate_GetSignature));
  }

  /**
   * Issue a sender certificate.
   *
   * <p>{@code signingKey} must be the private key that corresponds to {@link #getKey}, or the
   * resulting certificate won't have a valid signature.
   */
  public SenderCertificate issue(
      ECPrivateKey signingKey,
      String senderUuid,
      Optional<String> senderE164,
      int senderDeviceId,
      ECPublicKey senderIdentityKey,
      long expiration) {
    try (NativeHandleGuard identityGuard = new NativeHandleGuard(senderIdentityKey);
        NativeHandleGuard serverCertificateGuard = new NativeHandleGuard(this);
        NativeHandleGuard serverPrivateGuard = new NativeHandleGuard(signingKey)) {
      return new SenderCertificate(
          filterExceptions(
              () ->
                  Native.SenderCertificate_New(
                      senderUuid,
                      senderE164.orElse(null),
                      senderDeviceId,
                      identityGuard.nativeHandle(),
                      expiration,
                      serverCertificateGuard.nativeHandle(),
                      serverPrivateGuard.nativeHandle())));
    }
  }

  /**
   * Issue a sender certificate.
   *
   * <p>{@code signingKey} must be the private key that corresponds to {@link #getKey}, or the
   * resulting certificate won't have a valid signature.
   */
  public SenderCertificate issue(
      ECPrivateKey signingKey,
      ServiceId sender,
      Optional<String> senderE164,
      int senderDeviceId,
      ECPublicKey senderIdentityKey,
      long expiration) {
    return issue(
        signingKey, sender.toString(), senderE164, senderDeviceId, senderIdentityKey, expiration);
  }
}
