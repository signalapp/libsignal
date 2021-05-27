package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolUntrustedIdentityException extends ProtocolException {
  public ProtocolUntrustedIdentityException(UntrustedIdentityException e, String sender, int senderDevice) {
    super(e, sender, senderDevice);
  }

  ProtocolUntrustedIdentityException(UntrustedIdentityException e, UnidentifiedSenderMessageContent content) {
    super(e, content);
  }
}
