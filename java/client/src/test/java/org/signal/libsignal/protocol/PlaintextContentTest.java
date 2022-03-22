//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import org.junit.Test;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.DecryptionErrorMessage;
import org.signal.libsignal.protocol.message.PlaintextContent;
import org.signal.libsignal.protocol.util.Hex;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class PlaintextContentTest {
  @Test
  public void testRoundTripSerialization() throws Exception {
    // We don't have the whole Content proto exposed at the Java level in this project,
    // so just check the literal bytes that we expect.
    byte[] expectedPlaintextBody = new byte[] {
      // DecryptionErrorMessage field, 9 bytes long
      (byte)0x42, (byte)0x09,
      // The serialized DecryptionErrorMessage
      (byte)0x10, (byte)0x80, (byte)0xb8, (byte)0xbe,
      (byte)0x97, (byte)0xe1, (byte)0x2f, (byte)0x18,
      (byte)0x08,
      // Tail padding marker
      (byte)0x80,
    };

    long timestamp = 1640995200000L;
    int originalDeviceId = 8;

    // DEMs don't extract any information from the original message for a SenderKey message,
    // so we use that here to avoid having to construct a valid original message.
    DecryptionErrorMessage decryptionErrorMessage = DecryptionErrorMessage.forOriginalMessage(
      new byte[] {}, CiphertextMessage.SENDERKEY_TYPE, timestamp, originalDeviceId);

    byte[] serializedDEM = decryptionErrorMessage.serialize();
    assertArrayEquals(
      "expectedBody needs updating",
      serializedDEM,
      Arrays.copyOfRange(expectedPlaintextBody, 2, 2 + serializedDEM.length));

    byte[] serializedPlaintextContent = new PlaintextContent(decryptionErrorMessage).serialize();
    byte[] deserializedPlaintextBody = new PlaintextContent(serializedPlaintextContent).getBody();
    assertArrayEquals(deserializedPlaintextBody, expectedPlaintextBody);
  }

  @Test
  public void testDeserializationRejectsGarbage() throws Exception {
    try {
      new PlaintextContent(new byte[] {});
      fail();
    } catch (InvalidMessageException e) {}

    try {
      new PlaintextContent(new byte[] {(byte)0});
      fail();
    } catch (InvalidVersionException e) {}
  }
}
