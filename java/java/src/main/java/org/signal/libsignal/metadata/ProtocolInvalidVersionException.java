package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolInvalidVersionException extends ProtocolException {
  public ProtocolInvalidVersionException(InvalidVersionException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  public ProtocolInvalidVersionException(InvalidVersionException e, String sender, int senderDevice, int contentHint, Optional<byte[]> groupId) {
    super(e, sender, senderDevice, contentHint, groupId);
  }
}
