//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.metadata.protocol;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.Optional;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.libsignal.protocol.message.CiphertextMessage;

public class UnidentifiedSenderMessageContent implements NativeHandleGuard.Owner {
  // Must be kept in sync with sealed_sender.proto.
  public static final int CONTENT_HINT_DEFAULT = 0;
  public static final int CONTENT_HINT_RESENDABLE = 1;
  public static final int CONTENT_HINT_IMPLICIT = 2;

  private final long unsafeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.UnidentifiedSenderMessageContent_Destroy(this.unsafeHandle);
  }

  public UnidentifiedSenderMessageContent(long nativeHandle) {
    this.unsafeHandle = nativeHandle;
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public UnidentifiedSenderMessageContent(byte[] serialized)
      throws InvalidMetadataMessageException, InvalidCertificateException {
    try {
      this.unsafeHandle = Native.UnidentifiedSenderMessageContent_Deserialize(serialized);
    } catch (Exception e) {
      throw new InvalidMetadataMessageException(e);
    }
  }

  public UnidentifiedSenderMessageContent(
      CiphertextMessage message,
      SenderCertificate senderCertificate,
      int contentHint,
      Optional<byte[]> groupId) {
    try (NativeHandleGuard certificateGuard = new NativeHandleGuard(senderCertificate)) {
      this.unsafeHandle =
          filterExceptions(
              () ->
                  Native.UnidentifiedSenderMessageContent_New(
                      message, certificateGuard.nativeHandle(), contentHint, groupId.orElse(null)));
    }
  }

  public int getType() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.UnidentifiedSenderMessageContent_GetMsgType(guard.nativeHandle()));
    }
  }

  public SenderCertificate getSenderCertificate() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return new SenderCertificate(
          filterExceptions(
              () -> Native.UnidentifiedSenderMessageContent_GetSenderCert(guard.nativeHandle())));
    }
  }

  public byte[] getContent() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.UnidentifiedSenderMessageContent_GetContents(guard.nativeHandle()));
    }
  }

  public byte[] getSerialized() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.UnidentifiedSenderMessageContent_GetSerialized(guard.nativeHandle()));
    }
  }

  public int getContentHint() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return filterExceptions(
          () -> Native.UnidentifiedSenderMessageContent_GetContentHint(guard.nativeHandle()));
    }
  }

  public Optional<byte[]> getGroupId() {
    try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
      return Optional.ofNullable(
          filterExceptions(
              () -> Native.UnidentifiedSenderMessageContent_GetGroupId(guard.nativeHandle())));
    }
  }
}
