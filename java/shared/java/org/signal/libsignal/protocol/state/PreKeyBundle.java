/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.state;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;

/**
 * A class that contains a remote PreKey and collection
 * of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  // -1 is treated as Option<u32>::None by the bridging layer
  public static final int NULL_PRE_KEY_ID = -1;

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.PreKeyBundle_Destroy(this.unsafeHandle);
  }

  public PreKeyBundle(int registrationId, int deviceId, int preKeyId, ECPublicKey preKeyPublic,
                      int signedPreKeyId, ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                      IdentityKey identityKey) {
    this(
      registrationId,
      deviceId,
      preKeyId,
      preKeyPublic,
      signedPreKeyId,
      signedPreKeyPublic,
      signedPreKeySignature,
      identityKey,
      NULL_PRE_KEY_ID,
      null,
      null);
  }

  public PreKeyBundle(int registrationId, int deviceId, int preKeyId, ECPublicKey preKeyPublic,
                      int signedPreKeyId, ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                      IdentityKey identityKey, int kyberPreKeyId, KEMPublicKey kyberPreKeyPublic,
                      byte[] kyberPreKeySignature)
  {
    try (
      NativeHandleGuard preKeyPublicGuard = new NativeHandleGuard(preKeyPublic);
      NativeHandleGuard signedPreKeyPublicGuard = new NativeHandleGuard(signedPreKeyPublic);
      NativeHandleGuard identityKeyGuard = new NativeHandleGuard(identityKey.getPublicKey());
      NativeHandleGuard kyberPreKeyPublicGuard = new NativeHandleGuard(kyberPreKeyPublic);
    ) {
      byte[] kyberSignature = kyberPreKeySignature == null ? new byte[]{} : kyberPreKeySignature;
      this.unsafeHandle = Native.PreKeyBundle_New(
        registrationId,
        deviceId,
        preKeyId,
        preKeyPublicGuard.nativeHandle(),
        signedPreKeyId,
        signedPreKeyPublicGuard.nativeHandle(),
        signedPreKeySignature,
        identityKeyGuard.nativeHandle(),
        kyberPreKeyId,
        kyberPreKeyPublicGuard.nativeHandle(),
        kyberSignature);
    }
  }

  /**
   * @return the device ID this PreKey belongs to.
   */
  public int getDeviceId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyBundle_GetDeviceId(guard.nativeHandle());
    }
  }

  /**
   * @return the unique pre key ID or -1 if the bundle has none.
   */
  public int getPreKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyBundle_GetPreKeyId(guard.nativeHandle());
    }
  }

  /**
   * @return the public key for this PreKey.
   */
  public ECPublicKey getPreKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      long handle = Native.PreKeyBundle_GetPreKeyPublic(guard.nativeHandle());
      if (handle != 0) {
        return new ECPublicKey(handle);
      }
      return null;
    }
  }

  /**
   * @return the unique key ID for this signed prekey.
   */
  public int getSignedPreKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyBundle_GetSignedPreKeyId(guard.nativeHandle());
    }
  }

  /**
   * @return the signed prekey for this PreKeyBundle.
   */
  public ECPublicKey getSignedPreKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.PreKeyBundle_GetSignedPreKeyPublic(guard.nativeHandle()));
    }
  }

  /**
   * @return the signature over the signed prekey.
   */
  public byte[] getSignedPreKeySignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyBundle_GetSignedPreKeySignature(guard.nativeHandle());
    }
  }

  /**
   * @return the {@link org.signal.libsignal.protocol.IdentityKey} of this PreKeys owner.
   */
  public IdentityKey getIdentityKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new IdentityKey(new ECPublicKey(Native.PreKeyBundle_GetIdentityKey(guard.nativeHandle())));
    }
  }

  /**
   * @return the registration ID associated with this PreKey.
   */
  public int getRegistrationId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyBundle_GetRegistrationId(guard.nativeHandle());
    }
  }

  /**
   * @return the unique key ID for the Kyber prekey or -1 if the bundle has none.
   */
  public int getKyberPreKeyId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.PreKeyBundle_GetKyberPreKeyId(guard.nativeHandle());
    }
  }

  /**
   * @return the public key for this Kyber prekey.
   */
  public KEMPublicKey getKyberPreKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      long handle = Native.PreKeyBundle_GetKyberPreKeyPublic(guard.nativeHandle());
      if (handle != 0) {
        return new KEMPublicKey(handle);
      }
      return null;
    }
  }

  /**
   * @return the signature over the kyber prekey.
   */
  public byte[] getKyberPreKeySignature() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      byte[] signature = Native.PreKeyBundle_GetKyberPreKeySignature(guard.nativeHandle());
      if (signature.length == 0) {
        return null;
      }
      return signature;
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
