package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.util.guava.Optional;

public abstract class ProtocolException extends Exception {

  private final String sender;
  private final int senderDevice;
  private final int contentHint;
  private final Optional<byte[]> groupId;

  public ProtocolException(Exception e, String sender, int senderDevice) {
    this(e, sender, senderDevice, UnidentifiedSenderMessageContent.CONTENT_HINT_DEFAULT, Optional.<byte[]>absent());
  }

  public ProtocolException(Exception e, String sender, int senderDevice, int contentHint, Optional<byte[]> groupId) {
    this.sender       = sender;
    this.senderDevice = senderDevice;
    this.contentHint  = contentHint;
    this.groupId      = groupId;
  }

  public String getSender() {
    return sender;
  }

  public int getSenderDevice() {
    return senderDevice;
  }

  public int getContentHint() {
    return contentHint;
  }

  public Optional<byte[]> getGroupId() {
    return groupId;
  }
}
