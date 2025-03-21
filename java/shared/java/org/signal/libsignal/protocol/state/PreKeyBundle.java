//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;

/**
 * A class that contains a remote PreKey and collection of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle extends NativeHandleGuard.SimpleOwner {
  // -1 is treated as Option<u32>::None by the bridging layer
  public static final int NULL_PRE_KEY_ID = -1;

  @Override
  protected void release(long nativeHandle) {
    Native.PreKeyBundle_Destroy(nativeHandle);
  }

  public PreKeyBundle(
      int registrationId,
      int deviceId,
      int preKeyId,
      ECPublicKey preKeyPublic,
      int signedPreKeyId,
      ECPublicKey signedPreKeyPublic,
      byte[] signedPreKeySignature,
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

  public PreKeyBundle(
      int registrationId,
      int deviceId,
      int preKeyId,
      ECPublicKey preKeyPublic,
      int signedPreKeyId,
      ECPublicKey signedPreKeyPublic,
      byte[] signedPreKeySignature,
      IdentityKey identityKey,
      int kyberPreKeyId,
      KEMPublicKey kyberPreKeyPublic,
      byte[] kyberPreKeySignature) {
    super(
        PreKeyBundle.createNativeFrom(
            registrationId,
            deviceId,
            preKeyId,
            preKeyPublic,
            signedPreKeyId,
            signedPreKeyPublic,
            signedPreKeySignature,
            identityKey,
            kyberPreKeyId,
            kyberPreKeyPublic,
            kyberPreKeySignature));
  }

  private static long createNativeFrom(
      int registrationId,
      int deviceId,
      int preKeyId,
      ECPublicKey preKeyPublic,
      int signedPreKeyId,
      ECPublicKey signedPreKeyPublic,
      byte[] signedPreKeySignature,
      IdentityKey identityKey,
      int kyberPreKeyId,
      KEMPublicKey kyberPreKeyPublic,
      byte[] kyberPreKeySignature) {
    try (NativeHandleGuard preKeyPublicGuard = new NativeHandleGuard(preKeyPublic);
        NativeHandleGuard signedPreKeyPublicGuard = new NativeHandleGuard(signedPreKeyPublic);
        NativeHandleGuard identityKeyGuard = new NativeHandleGuard(identityKey.getPublicKey());
        NativeHandleGuard kyberPreKeyPublicGuard = new NativeHandleGuard(kyberPreKeyPublic); ) {
      byte[] kyberSignature = kyberPreKeySignature == null ? new byte[] {} : kyberPreKeySignature;
      return filterExceptions(
          () ->
              Native.PreKeyBundle_New(
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
                  kyberSignature));
    }
  }

  /**
   * @return the device ID this PreKey belongs to.
   */
  public int getDeviceId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetDeviceId));
  }

  /**
   * @return the unique pre key ID or -1 if the bundle has none.
   */
  public int getPreKeyId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetPreKeyId));
  }

  /**
   * @return the public key for this PreKey.
   */
  public ECPublicKey getPreKey() {
    long handle = filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetPreKeyPublic));
    if (handle != 0) {
      return new ECPublicKey(handle);
    }
    return null;
  }

  /**
   * @return the unique key ID for this signed prekey.
   */
  public int getSignedPreKeyId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetSignedPreKeyId));
  }

  /**
   * @return the signed prekey for this PreKeyBundle.
   */
  public ECPublicKey getSignedPreKey() {
    return new ECPublicKey(
        filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetSignedPreKeyPublic)));
  }

  /**
   * @return the signature over the signed prekey.
   */
  public byte[] getSignedPreKeySignature() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetSignedPreKeySignature));
  }

  /**
   * @return the {@link org.signal.libsignal.protocol.IdentityKey} of this PreKeys owner.
   */
  public IdentityKey getIdentityKey() {
    return new IdentityKey(
        new ECPublicKey(
            filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetIdentityKey))));
  }

  /**
   * @return the registration ID associated with this PreKey.
   */
  public int getRegistrationId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetRegistrationId));
  }

  /**
   * @return the unique key ID for the Kyber prekey or -1 if the bundle has none.
   */
  public int getKyberPreKeyId() {
    return filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetKyberPreKeyId));
  }

  /**
   * @return the public key for this Kyber prekey.
   */
  public KEMPublicKey getKyberPreKey() {
    long handle =
        filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetKyberPreKeyPublic));
    if (handle != 0) {
      return new KEMPublicKey(handle);
    }
    return null;
  }

  /**
   * @return the signature over the kyber prekey.
   */
  public byte[] getKyberPreKeySignature() {
    byte[] signature =
        filterExceptions(() -> guardedMapChecked(Native::PreKeyBundle_GetKyberPreKeySignature));
    if (signature.length == 0) {
      return null;
    }
    return signature;
  }
}
