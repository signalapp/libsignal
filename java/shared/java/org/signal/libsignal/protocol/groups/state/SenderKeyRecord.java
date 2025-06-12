//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.groups.state;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidMessageException;

/**
 * A durable representation of a set of SenderKeyStates for a specific (senderName, deviceId,
 * distributionId) tuple.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyRecord extends NativeHandleGuard.SimpleOwner {
  @Override
  protected void release(long nativeHandle) {
    Native.SenderKeyRecord_Destroy(nativeHandle);
  }

  @CalledFromNative
  public SenderKeyRecord(long nativeHandle) {
    super(nativeHandle);
  }

  // FIXME: This shouldn't be considered a "message".
  public SenderKeyRecord(byte[] serialized) throws InvalidMessageException {
    super(
        filterExceptions(
            InvalidMessageException.class, () -> Native.SenderKeyRecord_Deserialize(serialized)));
  }

  public byte[] serialize() {
    return filterExceptions(() -> guardedMapChecked(Native::SenderKeyRecord_GetSerialized));
  }
}
