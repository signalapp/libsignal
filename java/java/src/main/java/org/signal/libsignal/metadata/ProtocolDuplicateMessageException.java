package org.signal.libsignal.metadata;

import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolDuplicateMessageException extends ProtocolException {
  public ProtocolDuplicateMessageException(Exception e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  public ProtocolDuplicateMessageException(Exception e, String sender, int senderDevice, int contentHint, Optional<byte[]> groupId) {
    super(e, sender, senderDevice, contentHint, groupId);
  }
}
