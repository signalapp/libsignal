package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.signal.libsignal.protocol.InvalidMessageException;

public class ProtocolInvalidMessageException extends ProtocolException {
  public ProtocolInvalidMessageException(InvalidMessageException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolInvalidMessageException(InvalidMessageException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
