//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

/**
 * Holder for public and private identity key pair.
 *
 * @author Moxie Marlinspike
 */
public class IdentityKeyPair {
  private final IdentityKey publicKey;
  private final ECPrivateKey privateKey;

  public IdentityKeyPair(IdentityKey publicKey, ECPrivateKey privateKey) {
    this.publicKey = publicKey;
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

  @CalledFromNative
  public byte[] serialize() {
    try (NativeHandleGuard publicKey = new NativeHandleGuard(this.publicKey.getPublicKey());
        NativeHandleGuard privateKey = new NativeHandleGuard(this.privateKey); ) {
      return Native.IdentityKeyPair_Serialize(publicKey.nativeHandle(), privateKey.nativeHandle());
    }
  }

  public byte[] signAlternateIdentity(IdentityKey other) {
    try (NativeHandleGuard publicKey = new NativeHandleGuard(this.publicKey.getPublicKey());
        NativeHandleGuard privateKey = new NativeHandleGuard(this.privateKey);
        NativeHandleGuard otherPublic = new NativeHandleGuard(other.getPublicKey()); ) {
      return filterExceptions(
          () ->
              Native.IdentityKeyPair_SignAlternateIdentity(
                  publicKey.nativeHandle(), privateKey.nativeHandle(), otherPublic.nativeHandle()));
    }
  }
}
