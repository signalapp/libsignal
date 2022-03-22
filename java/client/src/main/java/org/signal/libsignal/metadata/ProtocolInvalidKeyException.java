package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.signal.libsignal.protocol.InvalidKeyException;

public class ProtocolInvalidKeyException extends ProtocolException {
  public ProtocolInvalidKeyException(InvalidKeyException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolInvalidKeyException(InvalidKeyException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
