/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.whispersystems.libsignal.state.StorageProtos.RecordStructure;
import static org.whispersystems.libsignal.state.StorageProtos.SessionStructure;

/**
 * A SessionRecord encapsulates the state of an ongoing session.
 *
 * @author Moxie Marlinspike
 */
public class SessionRecord {

  private static final int ARCHIVED_STATES_MAX_LENGTH = 40;

  private SessionState             sessionState   = new SessionState();
  private LinkedList<SessionState> previousStates = new LinkedList<>();
  private boolean                  fresh          = false;

  public SessionRecord() {
    this.fresh = true;
  }

  public SessionRecord(SessionState sessionState) {
    this.sessionState = sessionState;
    this.fresh        = false;
  }

  public SessionRecord(byte[] serialized) throws IOException {
    RecordStructure record = RecordStructure.parseFrom(serialized);
    this.sessionState = new SessionState(record.getCurrentSession());
    this.fresh        = false;

    for (SessionStructure previousStructure : record.getPreviousSessionsList()) {
      previousStates.add(new SessionState(previousStructure));
    }
  }

  public SessionState getSessionState() {
    return sessionState;
  }

  /**
   * Move the current {@link SessionState} into the list of "previous" session states,
   * and replace the current {@link org.whispersystems.libsignal.state.SessionState}
   * with a fresh reset instance.
   */
  public void archiveCurrentState() {
    promoteState(new SessionState());
  }

  private void promoteState(SessionState promotedState) {
    this.previousStates.addFirst(sessionState);
    this.sessionState = promotedState;

    if (previousStates.size() > ARCHIVED_STATES_MAX_LENGTH) {
      previousStates.removeLast();
    }
  }

  /**
   * @return a serialized version of the current SessionRecord.
   */
  public byte[] serialize() {
    List<SessionStructure> previousStructures = new LinkedList<>();

    for (SessionState previousState : previousStates) {
      previousStructures.add(previousState.getStructure());
    }

    RecordStructure record = RecordStructure.newBuilder()
                                            .setCurrentSession(sessionState.getStructure())
                                            .addAllPreviousSessions(previousStructures)
                                            .build();

    return record.toByteArray();
  }

}
