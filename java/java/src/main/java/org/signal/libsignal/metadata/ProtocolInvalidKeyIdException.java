package org.signal.libsignal.metadata;

import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolInvalidKeyIdException extends ProtocolException {
  public ProtocolInvalidKeyIdException(Exception e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  public ProtocolInvalidKeyIdException(Exception e, String sender, int senderDevice, int contentHint, Optional<byte[]> groupId) {
    super(e, sender, senderDevice, contentHint, groupId);
  }
}
