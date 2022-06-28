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

/**
 * A class that contains a remote PreKey and collection
 * of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.PreKeyBundle_Destroy(this.unsafeHandle);
  }

  public PreKeyBundle(int registrationId, int deviceId, int preKeyId, ECPublicKey preKeyPublic,
                      int signedPreKeyId, ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                      IdentityKey identityKey)
  {
    try (
      NativeHandleGuard preKeyPublicGuard = new NativeHandleGuard(preKeyPublic);
      NativeHandleGuard signedPreKeyPublicGuard = new NativeHandleGuard(signedPreKeyPublic);
      NativeHandleGuard identityKeyGuard = new NativeHandleGuard(identityKey.getPublicKey());
    ) {
      this.unsafeHandle = Native.PreKeyBundle_New(
        registrationId,
        deviceId,
        preKeyId,
        preKeyPublicGuard.nativeHandle(),
        signedPreKeyId,
        signedPreKeyPublicGuard.nativeHandle(),
        signedPreKeySignature,
        identityKeyGuard.nativeHandle());
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
   * @return the unique key ID for this PreKey.
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
   * @return the signature over the signed  prekey.
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

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
