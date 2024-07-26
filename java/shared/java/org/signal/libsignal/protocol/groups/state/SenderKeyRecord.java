//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.groups.state;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.InvalidMessageException;

/**
 * A durable representation of a set of SenderKeyStates for a specific (senderName, deviceId,
 * distributionId) tuple.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.SenderKeyRecord_Destroy(this.unsafeHandle);
  }

  public SenderKeyRecord(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  // FIXME: This shouldn't be considered a "message".
  public SenderKeyRecord(byte[] serialized) throws InvalidMessageException {
    this.unsafeHandle =
        filterExceptions(
            InvalidMessageException.class, () -> Native.SenderKeyRecord_Deserialize(serialized));
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(() -> Native.SenderKeyRecord_GetSerialized(guard.nativeHandle()));
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
