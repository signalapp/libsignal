/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups.state;

import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.StorageProtos;

import java.io.IOException;
import java.util.LinkedList;

import static org.whispersystems.libsignal.state.StorageProtos.SenderKeyRecordStructure;

/**
 * A durable representation of a set of SenderKeyStates for a specific
 * SenderKeyName.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyRecord {

  private LinkedList<SenderKeyState> senderKeyStates = new LinkedList<>();

  public SenderKeyRecord() {}

  public SenderKeyRecord(byte[] serialized) throws IOException {
    SenderKeyRecordStructure senderKeyRecordStructure = SenderKeyRecordStructure.parseFrom(serialized);

    for (StorageProtos.SenderKeyStateStructure structure : senderKeyRecordStructure.getSenderKeyStatesList()) {
      this.senderKeyStates.add(new SenderKeyState(structure));
    }
  }

  public byte[] serialize() {
    SenderKeyRecordStructure.Builder recordStructure = SenderKeyRecordStructure.newBuilder();

    for (SenderKeyState senderKeyState : senderKeyStates) {
      recordStructure.addSenderKeyStates(senderKeyState.getStructure());
    }

    return recordStructure.build().toByteArray();
  }
}
