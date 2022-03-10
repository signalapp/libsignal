/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.text.ParseException;
import java.util.UUID;

public class SenderKeyMessage implements CiphertextMessage, NativeHandleGuard.Owner {

  private final long unsafeHandle;

  @Override
  protected void finalize() {
     Native.SenderKeyMessage_Destroy(this.unsafeHandle);
  }

  public SenderKeyMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public long unsafeNativeHandleWithoutGuard() {
    return unsafeHandle;
  }

  public SenderKeyMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    unsafeHandle = Native.SenderKeyMessage_Deserialize(serialized);
  }

  public UUID getDistributionId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyMessage_GetDistributionId(guard.nativeHandle());
    }
  }

  public int getChainId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyMessage_GetChainId(guard.nativeHandle());
    }
  }

  public int getIteration() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyMessage_GetIteration(guard.nativeHandle());
    }
  }

  public byte[] getCipherText() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyMessage_GetCipherText(guard.nativeHandle());
    }
  }

  public void verifySignature(ECPublicKey signatureKey)
      throws InvalidMessageException
  {
    try (
      NativeHandleGuard guard = new NativeHandleGuard(this);
      NativeHandleGuard keyGuard = new NativeHandleGuard(signatureKey);
    ) {
      if (!Native.SenderKeyMessage_VerifySignature(guard.nativeHandle(), keyGuard.nativeHandle())) {
        throw new InvalidMessageException("Invalid signature!");
      }
    }
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyMessage_GetSerialized(guard.nativeHandle());
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.SENDERKEY_TYPE;
  }
}
