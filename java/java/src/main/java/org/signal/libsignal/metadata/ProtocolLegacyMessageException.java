package org.signal.libsignal.metadata;


import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.util.guava.Optional;

public class ProtocolLegacyMessageException extends ProtocolException {
  public ProtocolLegacyMessageException(LegacyMessageException e, String sender, int senderDeviceId) {
    super(e, sender, senderDeviceId);
  }

  public ProtocolLegacyMessageException(LegacyMessageException e, String sender, int senderDeviceId, int contentHint, Optional<byte[]> groupId) {
    super(e, sender, senderDeviceId, contentHint, groupId);
  }
}
