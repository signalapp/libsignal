/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * Holder for public and private identity key pair.
 *
 * @author Moxie Marlinspike
 */
public class IdentityKeyPair {
  private final IdentityKey  publicKey;
  private final ECPrivateKey privateKey;

  public IdentityKeyPair(IdentityKey publicKey, ECPrivateKey privateKey) {
    this.publicKey  = publicKey;
    this.privateKey = privateKey;
  }

  public IdentityKeyPair(byte[] serialized) {
    long[] tuple = Native.IdentityKeyPair_Deserialize(serialized);
    long publicKeyHandle = tuple[0];
    long privateKeyHandle = tuple[1];

    this.publicKey = new IdentityKey(publicKeyHandle);
    this.privateKey = new ECPrivateKey(privateKeyHandle);
  }

  public static IdentityKeyPair generate() {
    ECKeyPair keyPair = Curve.generateKeyPair();
    ECPrivateKey privateKey = keyPair.getPrivateKey();
    ECPublicKey publicKey = keyPair.getPublicKey();
    return new IdentityKeyPair(new IdentityKey(publicKey), privateKey);
  }

  public IdentityKey getPublicKey() {
    return publicKey;
  }

  public ECPrivateKey getPrivateKey() {
    return privateKey;
  }

  public byte[] serialize() {
    try (
      NativeHandleGuard publicKey = new NativeHandleGuard(this.publicKey.getPublicKey());
      NativeHandleGuard privateKey = new NativeHandleGuard(this.privateKey);
    ) {
      return Native.IdentityKeyPair_Serialize(publicKey.nativeHandle(), privateKey.nativeHandle());
    }
  }

  public byte[] signAlternateIdentity(IdentityKey other) {
    try (
      NativeHandleGuard publicKey = new NativeHandleGuard(this.publicKey.getPublicKey());
      NativeHandleGuard privateKey = new NativeHandleGuard(this.privateKey);
      NativeHandleGuard otherPublic = new NativeHandleGuard(other.getPublicKey());
    ) {
      return Native.IdentityKeyPair_SignAlternateIdentity(publicKey.nativeHandle(), privateKey.nativeHandle(), otherPublic.nativeHandle());
    }
  }
}
