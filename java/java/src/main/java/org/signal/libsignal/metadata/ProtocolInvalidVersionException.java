package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolInvalidVersionException extends ProtocolException {
  public ProtocolInvalidVersionException(InvalidVersionException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolInvalidVersionException(InvalidVersionException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
