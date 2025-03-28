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

public class SenderCertificate extends NativeHandleGuard.SimpleOwner {
  @Override
  protected void release(long nativeHandle) {
    Native.SenderCertificate_Destroy(nativeHandle);
  }

  public SenderCertificate(byte[] serialized) throws InvalidCertificateException {
    super(SenderCertificate.createNativeFrom(serialized));
  }

  private static long createNativeFrom(byte[] serialized) throws InvalidCertificateException {
    try {
      return Native.SenderCertificate_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidCertificateException(e);
    }
  }

  public SenderCertificate(long nativeHandle) {
    super(nativeHandle);
  }

  public ServerCertificate getSigner() {
    return new ServerCertificate(
        filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetServerCertificate)));
  }

  public ECPublicKey getKey() {
    return new ECPublicKey(
        filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetKey)));
  }

  public int getSenderDeviceId() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetDeviceId));
  }

  public String getSenderUuid() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetSenderUuid));
  }

  public Optional<String> getSenderE164() {
    return Optional.ofNullable(
        filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetSenderE164)));
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
    return filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetExpiration));
  }

  public byte[] getSerialized() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetSerialized));
  }

  public byte[] getCertificate() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetCertificate));
  }

  public byte[] getSignature() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderCertificate_GetSignature));
  }
}
