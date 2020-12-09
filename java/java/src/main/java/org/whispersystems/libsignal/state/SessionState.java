/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;
import java.io.IOException;

public class SessionState {
  private long handle;

  @Override
  protected void finalize() {
     Native.SessionState_Destroy(this.handle);
  }

  public SessionState(byte[] serialized) throws IOException {
    this.handle = Native.SessionState_Deserialize(serialized);
  }

  SessionState(long handle) {
    this.handle = handle;
  }

  // Used by Android
  public int getSessionVersion() {
    return Native.SessionState_GetSessionVersion(this.handle);
  }

  // Used by Android
  public boolean hasSenderChain() {
    return Native.SessionState_HasSenderChain(this.handle);
  }

  public byte[] serialize() {
    return Native.SessionState_Serialized(this.handle);
  }

  long nativeHandle() {
    return this.handle;
  }
}
