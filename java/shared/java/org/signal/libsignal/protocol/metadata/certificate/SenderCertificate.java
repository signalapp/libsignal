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
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class SenderCertificate implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.SenderCertificate_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public SenderCertificate(byte[] serialized) throws InvalidCertificateException {
    try {
      unsafeHandle = Native.SenderCertificate_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  public SenderCertificate(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public ServerCertificate getSigner() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ServerCertificate(
          filterExceptions(
              () -> Native.SenderCertificate_GetServerCertificate(guard.nativeHandle())));
    }
  }

  public ECPublicKey getKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(
          filterExceptions(() -> Native.SenderCertificate_GetKey(guard.nativeHandle())));
    }
  }

  public int getSenderDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderCertificate_GetDeviceId(guard.nativeHandle()));
    }
  }

  public String getSenderUuid() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderCertificate_GetSenderUuid(guard.nativeHandle()));
    }
  }

  public Optional<String> getSenderE164() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Optional.ofNullable(
          filterExceptions(() -> Native.SenderCertificate_GetSenderE164(guard.nativeHandle())));
    }
  }

  public String getSender() {
    return this.getSenderUuid();
  }

  /**
   * Returns an ACI if the sender is a valid UUID, {@code null} otherwise.
   *
   * <p>In a future release SenderCertificate will <em>only</em> support ACIs.
   */
  public ServiceId.Aci getSenderAci() {
    try {
      return ServiceId.Aci.parseFromString(getSender());
    } catch (ServiceId.InvalidServiceIdException e) {
      return null;
    }
  }

  public long getExpiration() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderCertificate_GetExpiration(guard.nativeHandle()));
    }
  }

  public byte[] getSerialized() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderCertificate_GetSerialized(guard.nativeHandle()));
    }
  }

  public byte[] getCertificate() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderCertificate_GetCertificate(guard.nativeHandle()));
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderCertificate_GetSignature(guard.nativeHandle()));
    }
  }
}
