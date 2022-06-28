package org.signal.libsignal.protocol.groups.state;

import org.signal.libsignal.protocol.groups.state.SenderKeyRecord;
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.util.Pair;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class InMemorySenderKeyStore implements SenderKeyStore {

  private final Map<Pair<SignalProtocolAddress, UUID>, SenderKeyRecord> store = new HashMap<>();

  @Override
  public void storeSenderKey(SignalProtocolAddress sender, UUID distributionId, SenderKeyRecord record) {
    store.put(new Pair<>(sender, distributionId), record);
  }

  @Override
  public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, UUID distributionId) {
    try {
      SenderKeyRecord record = store.get(new Pair<>(sender, distributionId));

      if (record == null) {
        return null;
      } else {
        return new SenderKeyRecord(record.serialize());
      }
    } catch (InvalidMessageException e) {
      throw new AssertionError(e);
    }
  }
}
