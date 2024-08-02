//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.util.Pair;

/**
 * A parsed Sealed Sender v2 "SentMessage", ready to be fanned out to multiple recipients.
 *
 * <p>The implementation assumes that every device for a particular recipient should use the same
 * key material.
 */
public class SealedSenderMultiRecipientMessage {
  private final byte[] fullMessageData;
  private final Map<ServiceId, Recipient> recipients;
  private final List<ServiceId> excludedRecipients;
  private final int offsetOfSharedData;

  /**
   * Per-recipient data for an SSv2 SentMessage.
   *
   * @see #messageForRecipient
   */
  public static class Recipient {
    private final byte[] devices;
    private final short[] registrationIds;
    private final int offsetOfRecipientSpecificKeyMaterial;
    // This is redundant in the current SSv2 format, but if we didn't have it, we'd be hardcoding
    // the length of the recipient-specific key material on the Java side.
    private final int lengthOfRecipientSpecificKeyMaterial;

    private Recipient(
        byte[] devices,
        short[] registrationIds,
        int offsetOfRecipientSpecificKeyMaterial,
        int lengthOfRecipientSpecificKeyMaterial) {
      assert devices.length == registrationIds.length;
      this.devices = devices;
      this.registrationIds = registrationIds;
      this.offsetOfRecipientSpecificKeyMaterial = offsetOfRecipientSpecificKeyMaterial;
      this.lengthOfRecipientSpecificKeyMaterial = lengthOfRecipientSpecificKeyMaterial;
    }

    /**
     * Returns the devices specified for this recipient.
     *
     * <p>A valid message should never have duplicate devices, but the parsing does not enforce
     * this.
     *
     * <p>The result is returned by reference; mutate it at your own detriment.
     */
    public byte[] getDevices() {
      return devices;
    }

    /**
     * Returns a stream of (device ID, registration ID) pairs.
     *
     * @see #getDevices
     */
    public Stream<Pair<Byte, Short>> getDevicesAndRegistrationIds() {
      return IntStream.range(0, devices.length)
          .mapToObj(i -> new Pair<>(devices[i], registrationIds[i]));
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof Recipient)) {
        return false;
      }
      Recipient otherRecipient = (Recipient) other;
      return Arrays.equals(devices, otherRecipient.devices)
          && Arrays.equals(registrationIds, otherRecipient.registrationIds)
          && offsetOfRecipientSpecificKeyMaterial
              == otherRecipient.offsetOfRecipientSpecificKeyMaterial
          && lengthOfRecipientSpecificKeyMaterial
              == otherRecipient.lengthOfRecipientSpecificKeyMaterial;
    }

    @Override
    public int hashCode() {
      // Leave out the length field, since in practice it will always be the same.
      return offsetOfRecipientSpecificKeyMaterial
          ^ Arrays.hashCode(devices)
          ^ Arrays.hashCode(registrationIds);
    }
  }

  /**
   * Parses the input as an SSv2 SentMessage.
   *
   * <p>The input is kept alive as long as the result is; it's used to implement {@link
   * #messageForRecipient} and {@link #serialized}.
   *
   * @throws InvalidVersionException if the <em>major</em> version of the sealed sender message is
   *     unrecognized
   * @throws InvalidMessageException if the message is malformed
   */
  public static SealedSenderMultiRecipientMessage parse(byte[] input)
      throws InvalidMessageException, InvalidVersionException {
    return (SealedSenderMultiRecipientMessage)
        Native.SealedSender_MultiRecipientParseSentMessage(input);
  }

  private SealedSenderMultiRecipientMessage(
      byte[] fullMessageData,
      Map<ServiceId, Recipient> recipients,
      List<ServiceId> excludedRecipients,
      int offsetOfSharedData) {
    this.fullMessageData = fullMessageData;
    this.recipients = recipients;
    this.excludedRecipients = excludedRecipients;
    this.offsetOfSharedData = offsetOfSharedData;
  }

  /**
   * Returns the serialized full message data.
   *
   * <p>The result is returned by reference; mutate it at your own detriment.
   */
  public byte[] serialized() {
    return fullMessageData;
  }

  /**
   * Returns the recipients parsed from the message.
   *
   * <p>The iteration order of the resulting Map is deterministic: the same input message data will
   * produce the same output even across multiple runs.
   *
   * <p>The result is returned by reference; mutate it at your own detriment.
   */
  public Map<ServiceId, Recipient> getRecipients() {
    return recipients;
  }

  /**
   * Returns the recipients excluded from receiving the message.
   *
   * <p>This is enforced to be disjoint from the recipients in {@link #getRecipients}; it may be
   * used for authorization purposes or just to check that certain recipients were deliberately
   * excluded rather than accidentally.
   *
   * <p>The iteration order is deterministic: the same input message data will produce the same
   * output even across multiple runs.
   *
   * <p>The result is returned by reference; mutate it at your own detriment.
   */
  public List<ServiceId> getExcludedRecipients() {
    return excludedRecipients;
  }

  /**
   * Returns the Sealed Sender V2 "ReceivedMessage" payload for delivery to a particular recipient.
   *
   * <p>The same payload should be sent to all of the recipient's devices.
   */
  public byte[] messageForRecipient(Recipient recipient) {
    final int lengthOfSharedData = fullMessageData.length - offsetOfSharedData;
    final ByteBuffer bbuf = ByteBuffer.allocate(messageSizeForRecipient(recipient));
    bbuf.put((byte) 0x22); // The "original" Sealed Sender V2 version
    bbuf.put(
        fullMessageData,
        recipient.offsetOfRecipientSpecificKeyMaterial,
        recipient.lengthOfRecipientSpecificKeyMaterial);
    bbuf.put(fullMessageData, offsetOfSharedData, lengthOfSharedData);
    return bbuf.array();
  }

  /**
   * Returns the length of the Sealed Sender V2 "ReceivedMessage" payload for delivery to a
   * particular recipient, without copying any buffers.
   */
  public int messageSizeForRecipient(Recipient recipient) {
    final int lengthOfSharedData = fullMessageData.length - offsetOfSharedData;
    return 1 /* version signature */
        + recipient.lengthOfRecipientSpecificKeyMaterial
        + lengthOfSharedData;
  }

  private static final byte SERIALIZED_RECIPIENT_VIEW_VERSION = 0x01;
  private static final byte[] ZERO_DEVICE_IDS = new byte[0];
  private static final short[] ZERO_REGISTRATION_IDS = new short[0];

  /**
   * Returns a serialized view for a particular {@link Recipient}.
   *
   * <p>This may be used to optimize temporary storage for future delivery&mdash;a single copy of
   * the serialized message may be stored, and the full recipient list will not need to be reparsed
   * to deliver to a single recipient.
   *
   * @see #serialized()
   * @see #messageForRecipient(byte[], byte[])
   */
  public byte[] serializedRecipientView(Recipient recipient) {
    final ByteBuffer bbuf = ByteBuffer.allocate(1 + 4 + 4 + 4);
    bbuf.put(SERIALIZED_RECIPIENT_VIEW_VERSION);
    bbuf.putInt(offsetOfSharedData);
    bbuf.putInt(recipient.offsetOfRecipientSpecificKeyMaterial);
    bbuf.putInt(recipient.lengthOfRecipientSpecificKeyMaterial);
    assert !bbuf.hasRemaining();
    return bbuf.array();
  }

  /**
   * Returns the Sealed Sender V2 "ReceivedMessage" payload for delivery to a particular recipient
   * from its serialized view.
   *
   * <p>The same payload should be sent to all the recipient's devices.
   *
   * @see #serializedRecipientView(Recipient)
   */
  public static byte[] messageForRecipient(byte[] fullMessageData, byte[] serializedRecipientView)
      throws InvalidVersionException {

    if (serializedRecipientView.length != 13) {
      throw new IllegalArgumentException(
          "Invalid length for serialized view: " + serializedRecipientView.length);
    }

    final ByteBuffer wrapped = ByteBuffer.wrap(serializedRecipientView);
    final byte version = wrapped.get();

    if (version != SERIALIZED_RECIPIENT_VIEW_VERSION) {
      throw new InvalidVersionException("Recipient view version " + version + " is not supported");
    }

    final int offsetOfSharedData = wrapped.getInt();
    final int offsetOfRecipientSpecificKeyMaterial = wrapped.getInt();
    final int lengthOfRecipientSpecificKeyMaterial = wrapped.getInt();

    assert !wrapped.hasRemaining();

    // Device, registration, and excluded service IDs aren't used or checked in this path, so we can
    // use empty arrays.
    final Recipient recipient =
        new Recipient(
            ZERO_DEVICE_IDS,
            ZERO_REGISTRATION_IDS,
            offsetOfRecipientSpecificKeyMaterial,
            lengthOfRecipientSpecificKeyMaterial);
    final SealedSenderMultiRecipientMessage message =
        new SealedSenderMultiRecipientMessage(
            fullMessageData, Collections.emptyMap(), Collections.emptyList(), offsetOfSharedData);

    return message.messageForRecipient(recipient);
  }
}
