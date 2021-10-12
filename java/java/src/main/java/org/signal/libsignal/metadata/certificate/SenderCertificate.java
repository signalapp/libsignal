package org.signal.libsignal.metadata.certificate;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;

import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.util.guava.Optional;

public class SenderCertificate implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
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
      return new ServerCertificate(Native.SenderCertificate_GetServerCertificate(guard.nativeHandle()));
    }
  }

  public ECPublicKey getKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.SenderCertificate_GetKey(guard.nativeHandle()));
    }
  }

  public int getSenderDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderCertificate_GetDeviceId(guard.nativeHandle());
    }
  }

  public String getSenderUuid() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderCertificate_GetSenderUuid(guard.nativeHandle());
    }
  }

  public Optional<String> getSenderE164() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Optional.fromNullable(Native.SenderCertificate_GetSenderE164(guard.nativeHandle()));
    }
  }

  public String getSender() {
    return getSenderE164().or(getSenderUuid());
  }

  public long getExpiration() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderCertificate_GetExpiration(guard.nativeHandle());
    }
  }

  public byte[] getSerialized() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderCertificate_GetSerialized(guard.nativeHandle());
    }
  }

  public byte[] getCertificate() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderCertificate_GetCertificate(guard.nativeHandle());
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderCertificate_GetSignature(guard.nativeHandle());
    }
  }
}
