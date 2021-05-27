package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolNoSessionException extends ProtocolException {
  public ProtocolNoSessionException(NoSessionException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolNoSessionException(NoSessionException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
