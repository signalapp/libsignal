//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.util.Pair;

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

  public IdentityKeyPair(byte[] serialized) throws InvalidKeyException {
    try {
      @SuppressWarnings("unchecked")
      var pair = (Pair<Long, Long>) Native.IdentityKeyPair_Deserialize(serialized);
      this.publicKey = new IdentityKey(pair.first());
      this.privateKey = new ECPrivateKey(pair.second());
    } catch (Exception e) {
      throw new InvalidKeyException(e);
    }
  }

  public static IdentityKeyPair generate() {
    ECPrivateKey privateKey = ECPrivateKey.generate();
    ECPublicKey publicKey = privateKey.publicKey();
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
