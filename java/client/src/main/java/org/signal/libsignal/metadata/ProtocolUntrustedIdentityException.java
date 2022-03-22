package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.signal.libsignal.protocol.UntrustedIdentityException;

public class ProtocolUntrustedIdentityException extends ProtocolException {
  public ProtocolUntrustedIdentityException(UntrustedIdentityException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolUntrustedIdentityException(UntrustedIdentityException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
