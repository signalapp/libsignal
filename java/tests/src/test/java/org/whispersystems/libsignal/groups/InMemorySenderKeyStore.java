package org.whispersystems.libsignal.groups;

import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.util.Pair;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class InMemorySenderKeyStore implements SenderKeyStore {

  private final Map<Pair<SignalProtocolAddress, String>, SenderKeyRecord> store = new HashMap<>();

  @Override
  public void storeSenderKey(SignalProtocolAddress sender, String distributionId, SenderKeyRecord record) {
    store.put(new Pair(sender, distributionId), record);
  }

  @Override
  public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, String distributionId) {
    try {
      SenderKeyRecord record = store.get(new Pair(sender, distributionId));

      if (record == null) {
        return new SenderKeyRecord();
      } else {
        return new SenderKeyRecord(record.serialize());
      }
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }
}
