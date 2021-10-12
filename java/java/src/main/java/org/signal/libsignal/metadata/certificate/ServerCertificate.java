package org.signal.libsignal.metadata.certificate;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;

import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class ServerCertificate implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
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

  public int getKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ServerCertificate_GetKeyId(guard.nativeHandle());
    }
  }

  public ECPublicKey getKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.ServerCertificate_GetKey(guard.nativeHandle()));
    }
  }

  public byte[] getSerialized() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ServerCertificate_GetSerialized(guard.nativeHandle());
    }
  }

  public byte[] getCertificate() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ServerCertificate_GetCertificate(guard.nativeHandle());
    }
  }

  public byte[] getSignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.ServerCertificate_GetSignature(guard.nativeHandle());
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
