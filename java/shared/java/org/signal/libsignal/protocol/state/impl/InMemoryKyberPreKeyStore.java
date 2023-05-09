//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.protocol.state.impl;

import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class InMemoryKyberPreKeyStore implements KyberPreKeyStore {

  private final Map<Integer, byte[]> store = new HashMap<>();
  private final Set<Integer> used = new HashSet<>();

  @Override
  public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException {
    try {
      if (!store.containsKey(kyberPreKeyId)) {
        throw new InvalidKeyIdException("No such KyberPreKeyRecord! " + kyberPreKeyId);
      }

      return new KyberPreKeyRecord(store.get(kyberPreKeyId));
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public List<KyberPreKeyRecord> loadKyberPreKeys() {
    try {
      List<KyberPreKeyRecord> results = new LinkedList<>();

      for (byte[] serialized : store.values()) {
        results.add(new KyberPreKeyRecord(serialized));
      }

      return results;
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) {
    store.put(kyberPreKeyId, record.serialize());
  }

  @Override
  public boolean containsKyberPreKey(int kyberPreKeyId) {
    return store.containsKey(kyberPreKeyId);
  }

  @Override
  public void markKyberPreKeyUsed(int kyberPreKeyId) {
    //store.remove(kyberPreKeyId);
    used.add(kyberPreKeyId);
  }

  public boolean hasKyberPreKeyBeenUsed(int kyberPreKeyId) {
    return used.contains(kyberPreKeyId);
  }
}
