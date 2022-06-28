/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.message;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

import java.util.UUID;

public class SenderKeyDistributionMessage implements NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
     Native.SenderKeyDistributionMessage_Destroy(this.unsafeHandle);
  }

  public SenderKeyDistributionMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public SenderKeyDistributionMessage(byte[] serialized) throws InvalidMessageException, InvalidVersionException, LegacyMessageException, InvalidKeyException {
    unsafeHandle = Native.SenderKeyDistributionMessage_Deserialize(serialized);
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyDistributionMessage_GetSerialized(guard.nativeHandle());
    }
  }

  public UUID getDistributionId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyMessage_GetDistributionId(guard.nativeHandle());
    }
  }

  public int getIteration() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyDistributionMessage_GetIteration(guard.nativeHandle());
    }
  }

  public byte[] getChainKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyDistributionMessage_GetChainKey(guard.nativeHandle());
    }
  }

  public ECPublicKey getSignatureKey() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.SenderKeyDistributionMessage_GetSignatureKey(guard.nativeHandle()));
    }
  }

  public int getChainId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyDistributionMessage_GetChainId(guard.nativeHandle());
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
