/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.signal.libsignal.protocol.state.impl;

import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class InMemorySignedPreKeyStore implements SignedPreKeyStore {

  private final Map<Integer, byte[]> store = new HashMap<>();

  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    try {
      if (!store.containsKey(signedPreKeyId)) {
        throw new InvalidKeyIdException("No such SignedPreKeyRecord! " + signedPreKeyId);
      }

      return new SignedPreKeyRecord(store.get(signedPreKeyId));
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public List<SignedPreKeyRecord> loadSignedPreKeys() {
    try {
      List<SignedPreKeyRecord> results = new LinkedList<>();

      for (byte[] serialized : store.values()) {
        results.add(new SignedPreKeyRecord(serialized));
      }

      return results;
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
    store.put(signedPreKeyId, record.serialize());
  }

  @Override
  public boolean containsSignedPreKey(int signedPreKeyId) {
    return store.containsKey(signedPreKeyId);
  }

  @Override
  public void removeSignedPreKey(int signedPreKeyId) {
    store.remove(signedPreKeyId);
  }
}
