//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.message;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.UUID;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class SenderKeyMessage extends NativeHandleGuard.SimpleOwner
    implements CiphertextMessage, NativeHandleGuard.Owner {

  @Override
  protected void release(long nativeHandle) {
    Native.SenderKeyMessage_Destroy(nativeHandle);
  }

  @CalledFromNative
  public SenderKeyMessage(long nativeHandle) {
    super(nativeHandle);
  }

  public SenderKeyMessage(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException, LegacyMessageException {
    super(
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            LegacyMessageException.class,
            () -> Native.SenderKeyMessage_Deserialize(serialized)));
  }

  public UUID getDistributionId() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderKeyMessage_GetDistributionId));
  }

  public int getChainId() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderKeyMessage_GetChainId));
  }

  public int getIteration() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderKeyMessage_GetIteration));
  }

  public byte[] getCipherText() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderKeyMessage_GetCipherText));
  }

  public void verifySignature(ECPublicKey signatureKey) throws InvalidMessageException {
    try (NativeHandleGuard guard = new NativeHandleGuard(this);
        NativeHandleGuard keyGuard = new NativeHandleGuard(signatureKey); ) {
      if (!filterExceptions(
          InvalidMessageException.class,
          () ->
              Native.SenderKeyMessage_VerifySignature(
                  guard.nativeHandle(), keyGuard.nativeHandle()))) {
        throw new InvalidMessageException("Invalid signature!");
      }
    }
  }

  @Override
  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderKeyMessage_GetSerialized));
  }

  @Override
  public int getType() {
    return CiphertextMessage.SENDERKEY_TYPE;
  }
}
