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

public class ServerCertificate implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.ServerCertificate_Destroy(this.unsafeHandle);
  }

  public ServerCertificate(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public ServerCertificate(byte[] serialized) throws InvalidCertificateException {
    try {
      this.unsafeHandle = Native.ServerCertificate_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  /** Use {@code trustRoot} to generate and sign a new server certificate containing {@code key}. */
  public ServerCertificate(ECPrivateKey trustRoot, int keyId, ECPublicKey key) {
    try (NativeHandleGuard serverPublicGuard = new NativeHandleGuard(key);
        NativeHandleGuard trustRootPrivateGuard = new NativeHandleGuard(trustRoot)) {
      this.unsafeHandle =
          filterExceptions(
              () ->
                  Native.ServerCertificate_New(
                      keyId,
                      serverPublicGuard.nativeHandle(),
                      trustRootPrivateGuard.nativeHandle()));
    }
  }

  public int getKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ServerCertificate_GetKeyId(guard.nativeHandle()));
    }
  }

  public ECPublicKey getKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(
          filterExceptions(() -> Native.ServerCertificate_GetKey(guard.nativeHandle())));
    }
  }

  public byte[] getSerialized() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ServerCertificate_GetSerialized(guard.nativeHandle()));
    }
  }

  public byte[] getCertificate() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ServerCertificate_GetCertificate(guard.nativeHandle()));
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.ServerCertificate_GetSignature(guard.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
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
