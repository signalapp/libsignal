/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.signal.client.internal.Native;
import java.io.IOException;

/**
 * A SessionRecord encapsulates the state of an ongoing session.
 *
 * @author Moxie Marlinspike
 */
public class SessionRecord {

  long handle;

  @Override
  protected void finalize() {
     Native.SessionRecord_Destroy(this.handle);
  }

  public SessionRecord() {
    this.handle = Native.SessionRecord_NewFresh();
  }

  public SessionRecord(SessionState sessionState) {
    this.handle = Native.SessionRecord_FromSessionState(sessionState.nativeHandle());
  }

  public SessionRecord(byte[] serialized) throws IOException {
    this.handle = Native.SessionRecord_Deserialize(serialized);
  }

  public SessionState getSessionState() {
    return new SessionState(Native.SessionRecord_GetSessionState(this.handle));
  }

  /**
   * Move the current {@link SessionState} into the list of "previous" session states,
   * and replace the current {@link org.whispersystems.libsignal.state.SessionState}
   * with a fresh reset instance.
   */
  public void archiveCurrentState() {
    Native.SessionRecord_ArchiveCurrentState(this.handle);
  }

  /**
   * @return a serialized version of the current SessionRecord.
   */
  public byte[] serialize() {
    return Native.SessionRecord_Serialize(this.handle);
  }

}
