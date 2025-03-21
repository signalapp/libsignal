//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.message;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.UUID;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

public class SenderKeyDistributionMessage extends NativeHandleGuard.SimpleOwner {

  @Override
  protected void release(long nativeHandle) {
    Native.SenderKeyDistributionMessage_Destroy(nativeHandle);
  }

  public SenderKeyDistributionMessage(long nativeHandle) {
    super(nativeHandle);
  }

  public SenderKeyDistributionMessage(byte[] serialized)
      throws InvalidMessageException,
          InvalidVersionException,
          LegacyMessageException,
          InvalidKeyException {
    super(
        filterExceptions(
            InvalidMessageException.class,
            InvalidVersionException.class,
            LegacyMessageException.class,
            InvalidKeyException.class,
            () -> Native.SenderKeyDistributionMessage_Deserialize(serialized)));
  }

  public byte[] serialize() {
    return filterExceptions(
        () -> guardedMapChecked(Native::SenderKeyDistributionMessage_GetSerialized));
  }

  public UUID getDistributionId() {
    return filterExceptions(
        () -> guardedMapChecked(Native::SenderKeyDistributionMessage_GetDistributionId));
  }

  public int getIteration() {
    return filterExceptions(
        () -> guardedMapChecked(Native::SenderKeyDistributionMessage_GetIteration));
  }

  public byte[] getChainKey() {
    return filterExceptions(
        () -> guardedMapChecked(Native::SenderKeyDistributionMessage_GetChainKey));
  }

  public ECPublicKey getSignatureKey() {
    return new ECPublicKey(
        filterExceptions(
            () -> guardedMapChecked(Native::SenderKeyDistributionMessage_GetSignatureKey)));
  }

  public int getChainId() {
    return filterExceptions(
        () -> guardedMapChecked(Native::SenderKeyDistributionMessage_GetChainId));
  }
}
