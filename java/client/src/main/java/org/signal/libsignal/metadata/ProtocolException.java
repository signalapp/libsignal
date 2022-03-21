package org.signal.libsignal.metadata;

import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;

import java.util.Optional;

public abstract class ProtocolException extends Exception {

  private final Optional<UnidentifiedSenderMessageContent> content;
  private final String sender;
  private final int senderDevice;

  public ProtocolException(Exception e, String sender, int senderDevice) {
    super(e);
    this.content      = Optional.empty();
    this.sender       = sender;
    this.senderDevice = senderDevice;
  }

  ProtocolException(Exception e, UnidentifiedSenderMessageContent content) {
    super(e);
    this.content      = Optional.of(content);
    this.sender       = content.getSenderCertificate().getSender();
    this.senderDevice = content.getSenderCertificate().getSenderDeviceId();
  }

  public Optional<UnidentifiedSenderMessageContent> getUnidentifiedSenderMessageContent() {
    return content;
  }

  public String getSender() {
    return sender;
  }

  public int getSenderDevice() {
    return senderDevice;
  }

  public int getContentHint() {
    if (content.isPresent()) {
      return content.get().getContentHint();
    }
    return UnidentifiedSenderMessageContent.CONTENT_HINT_DEFAULT;
  }

  public Optional<byte[]> getGroupId() {
    if (content.isPresent()) {
      return content.get().getGroupId();
    }
    return Optional.<byte[]>empty();
  }
}
