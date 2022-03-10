/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;

import javax.crypto.spec.SecretKeySpec;

public class SignalMessage implements CiphertextMessage, NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  protected void finalize() {
     Native.SignalMessage_Destroy(this.unsafeHandle);
  }

  public SignalMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    unsafeHandle = Native.SignalMessage_Deserialize(serialized);
  }

  public SignalMessage(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public ECPublicKey getSenderRatchetKey()  {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new ECPublicKey(Native.SignalMessage_GetSenderRatchetKey(guard.nativeHandle()));
    }
  }

  public int getMessageVersion() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignalMessage_GetMessageVersion(guard.nativeHandle());
    }
  }

  public int getCounter() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignalMessage_GetCounter(guard.nativeHandle());
    }
  }

  public byte[] getBody() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignalMessage_GetBody(guard.nativeHandle());
    }
  }

  public void verifyMac(IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey)
      throws InvalidMessageException
  {
    try (
      NativeHandleGuard guard = new NativeHandleGuard(this);
      NativeHandleGuard senderIdentityGuard = new NativeHandleGuard(senderIdentityKey.getPublicKey());
      NativeHandleGuard receiverIdentityGuard = new NativeHandleGuard(receiverIdentityKey.getPublicKey());
    ) {
      if (!Native.SignalMessage_VerifyMac(
          guard.nativeHandle(),
          senderIdentityGuard.nativeHandle(),
          receiverIdentityGuard.nativeHandle(),
          macKey.getEncoded())) {
        throw new InvalidMessageException("Bad Mac!");
      }
    }
  }

  @Override
  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SignalMessage_GetSerialized(guard.nativeHandle());
    }
  }

  @Override
  public int getType() {
    return CiphertextMessage.WHISPER_TYPE;
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public static boolean isLegacy(byte[] message) {
    return message != null && message.length >= 1 &&
        ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
  }

}
