//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.message;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.util.ByteUtil;

public class SignalMessage extends NativeHandleGuard.SimpleOwner
    implements CiphertextMessage, NativeHandleGuard.Owner {
  @Override
  protected void release(long nativeHandle) {
    Native.SignalMessage_Destroy(nativeHandle);
  }

  public SignalMessage(byte[] serialized)
      throws InvalidMessageException,
          InvalidVersionException,
          InvalidKeyException,
          LegacyMessageException {
    super(
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            InvalidKeyException.class,
            LegacyMessageException.class,
            () -> Native.SignalMessage_Deserialize(serialized)));
  }

  @CalledFromNative
  public SignalMessage(long nativeHandle) {
    super(nativeHandle);
  }

  public ECPublicKey getSenderRatchetKey() {
    return new ECPublicKey(
        filterExceptions(() -> guardedMapChecked(Native::SignalMessage_GetSenderRatchetKey)));
  }

  public int getMessageVersion() {
    return filterExceptions(() -> guardedMapChecked(Native::SignalMessage_GetMessageVersion));
  }

  public int getCounter() {
    return filterExceptions(() -> guardedMapChecked(Native::SignalMessage_GetCounter));
  }

  public byte[] getBody() {
    return filterExceptions(() -> guardedMapChecked(Native::SignalMessage_GetBody));
  }

  public byte[] getPqRatchet() {
    return filterExceptions(() -> guardedMapChecked(Native::SignalMessage_GetPqRatchet));
  }

  @Override
  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::SignalMessage_GetSerialized));
  }

  @Override
  public int getType() {
    return CiphertextMessage.WHISPER_TYPE;
  }

  public static boolean isLegacy(byte[] message) {
    return message != null
        && message.length >= 1
        && ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
  }
}
