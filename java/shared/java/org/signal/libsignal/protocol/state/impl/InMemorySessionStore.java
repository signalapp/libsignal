/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.state.impl;

import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SessionStore;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class InMemorySessionStore implements SessionStore {

  private Map<SignalProtocolAddress, byte[]> sessions = new HashMap<>();

  public InMemorySessionStore() {}

  @Override
  public synchronized SessionRecord loadSession(SignalProtocolAddress remoteAddress) {
    try {
      if (containsSession(remoteAddress)) {
        return new SessionRecord(sessions.get(remoteAddress));
      } else {
        return null;
      }
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public synchronized List<SessionRecord> loadExistingSessions(List<SignalProtocolAddress> addresses) throws NoSessionException {
    List<SessionRecord> resultSessions = new LinkedList<>();
    for (SignalProtocolAddress remoteAddress : addresses) {
      byte[] serialized = sessions.get(remoteAddress);
      if (serialized == null) {
        throw new NoSessionException(remoteAddress, "no session for " + remoteAddress);
      }
      try {
        resultSessions.add(new SessionRecord(serialized));
      } catch (InvalidMessageException e) {
        throw new AssertionError(e);
      }
    }
    return resultSessions;
  }

  @Override
  public synchronized List<Integer> getSubDeviceSessions(String name) {
    List<Integer> deviceIds = new LinkedList<>();

    for (SignalProtocolAddress key : sessions.keySet()) {
      if (key.getName().equals(name) &&
          key.getDeviceId() != 1)
      {
        deviceIds.add(key.getDeviceId());
      }
    }

    return deviceIds;
  }

  @Override
  public synchronized void storeSession(SignalProtocolAddress address, SessionRecord record) {
    sessions.put(address, record.serialize());
  }

  @Override
  public synchronized boolean containsSession(SignalProtocolAddress address) {
    return sessions.containsKey(address);
  }

  @Override
  public synchronized void deleteSession(SignalProtocolAddress address) {
    sessions.remove(address);
  }

  @Override
  public synchronized void deleteAllSessions(String name) {
    for (SignalProtocolAddress key : sessions.keySet()) {
      if (key.getName().equals(name)) {
        sessions.remove(key);
      }
    }
  }
}
