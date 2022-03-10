/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups.state;

import org.signal.client.internal.Native;
import org.signal.client.internal.NativeHandleGuard;
import java.io.IOException;

/**
 * A durable representation of a set of SenderKeyStates for a specific
 * (senderName, deviceId, distributionId) tuple.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyRecord implements NativeHandleGuard.Owner {
  private final long unsafeHandle;

  @Override
  protected void finalize() {
    Native.SenderKeyRecord_Destroy(this.unsafeHandle);
  }

  public SenderKeyRecord() {
    this.unsafeHandle = Native.SenderKeyRecord_New();
  }

  public SenderKeyRecord(long unsafeHandle) {
    this.unsafeHandle = unsafeHandle;
  }

  public SenderKeyRecord(byte[] serialized) throws IOException {
    this.unsafeHandle = Native.SenderKeyRecord_Deserialize(serialized);
  }

  public byte[] serialize() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Native.SenderKeyRecord_GetSerialized(guard.nativeHandle());
    }
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }
}
