//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.Test;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.protocol.util.Pair;

public class SealedSenderMultiRecipientMessageTest {
  static final String VERSION_ACI_ONLY = "22";
  static final String VERSION_SERVICE_ID_AWARE = "23";
  static final String VERSION_RECIPIENT_MESSAGE = "22";

  static final String ACI_MARKER = "00";
  static final String PNI_MARKER = "01";

  static final String ALICE_UUID_BYTES = "9d0652a3dcc34d11975f74d61598733f";
  static final String ALICE_KEY_MATERIAL =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  static final String BOB_UUID_BYTES = "e80f7bbe5b94471ebd8c2173654ea3d1";
  static final String BOB_KEY_MATERIAL =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  static final String EVE_UUID_BYTES = "3f0f4734e3314434bd4f6d8f6ea6dcc7";
  static final String MALLORY_UUID_BYTES = "5d0881426fd74dbdaf00fdda1b3ce988";

  static final String SHARED_BYTES =
      "99999999999999999999999999999999999999999999999999999999999999999999";

  private void assertMessageForRecipient(
      final SealedSenderMultiRecipientMessage message,
      final SealedSenderMultiRecipientMessage.Recipient recipient,
      final String... expectedContentsHexParts) {
    final byte[] expectedContents = Hex.fromStringsCondensedAssert(expectedContentsHexParts);
    assertArrayEquals(expectedContents, message.messageForRecipient(recipient));
    assertEquals(expectedContents.length, message.messageSizeForRecipient(recipient));

    try {
      byte[] view =
          SealedSenderMultiRecipientMessage.messageForRecipient(
              message.serialized(), message.serializedRecipientView(recipient));
      assertArrayEquals(expectedContents, view);
    } catch (final Exception e) {
      throw new AssertionError("Should not have thrown", e);
    }
  }

  @Test
  public void simpleAciOnly() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_ACI_ONLY,
            // Count
            "03",
            // Recipient 1: UUID, Device ID and Registration ID, Key Material
            ALICE_UUID_BYTES,
            "0111aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2
            BOB_UUID_BYTES,
            "0111bb",
            BOB_KEY_MATERIAL,
            // Recipient 3 (note that it's another device of Bob's)
            BOB_UUID_BYTES,
            "0333bb",
            BOB_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 2);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa),
        });
    assertMessageForRecipient(message, alice, VERSION_ACI_ONLY, ALICE_KEY_MATERIAL, SHARED_BYTES);

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(BOB_UUID_BYTES)));
    assertNotNull(bob);
    assertArrayEquals(
        bob.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11bb), new Pair<>((byte) 0x03, (short) 0x33bb),
        });
    assertMessageForRecipient(message, bob, VERSION_ACI_ONLY, BOB_KEY_MATERIAL, SHARED_BYTES);
  }

  @Test
  public void aciOnlyWithRepeatedRecipient() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_ACI_ONLY,
            // Count
            "03",
            // Recipient 1: UUID, Device ID and Registration ID, Key Material
            ALICE_UUID_BYTES,
            "0111aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2
            BOB_UUID_BYTES,
            "0111bb",
            BOB_KEY_MATERIAL,
            // Recipient 3 (note that it's another device of Alice's)
            ALICE_UUID_BYTES,
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 2);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa), new Pair<>((byte) 0x03, (short) 0x33aa),
        });
    assertMessageForRecipient(message, alice, VERSION_ACI_ONLY, ALICE_KEY_MATERIAL, SHARED_BYTES);

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(BOB_UUID_BYTES)));
    assertNotNull(bob);
    assertArrayEquals(
        bob.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11bb),
        });
    assertMessageForRecipient(message, bob, VERSION_ACI_ONLY, BOB_KEY_MATERIAL, SHARED_BYTES);
  }

  @Test
  public void simpleServiceIds() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "03",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0111aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2
            PNI_MARKER,
            BOB_UUID_BYTES,
            "0111bb",
            BOB_KEY_MATERIAL,
            // Recipient 3 (note that it's another device of Bob's)
            PNI_MARKER,
            BOB_UUID_BYTES,
            "0333bb",
            BOB_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 2);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa),
        });
    assertMessageForRecipient(
        message, alice, VERSION_RECIPIENT_MESSAGE, ALICE_KEY_MATERIAL, SHARED_BYTES);

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(
                ServiceId.parseFromBinary(
                    Hex.fromStringsCondensedAssert(PNI_MARKER, BOB_UUID_BYTES)));
    assertNotNull(bob);
    assertArrayEquals(
        bob.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11bb), new Pair<>((byte) 0x03, (short) 0x33bb),
        });
    assertMessageForRecipient(
        message, bob, VERSION_RECIPIENT_MESSAGE, BOB_KEY_MATERIAL, SHARED_BYTES);
  }

  @Test
  public void serviceIdsWithRepeatedRecipient() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "03",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0111aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2
            PNI_MARKER,
            BOB_UUID_BYTES,
            "0111bb",
            BOB_KEY_MATERIAL,
            // Recipient 3 (note that it's another device of Alice's)
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 2);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa), new Pair<>((byte) 0x03, (short) 0x33aa),
        });
    assertMessageForRecipient(
        message, alice, VERSION_RECIPIENT_MESSAGE, ALICE_KEY_MATERIAL, SHARED_BYTES);

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(
                ServiceId.parseFromBinary(
                    Hex.fromStringsCondensedAssert(PNI_MARKER, BOB_UUID_BYTES)));
    assertNotNull(bob);
    assertArrayEquals(
        bob.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11bb),
        });
    assertMessageForRecipient(
        message, bob, VERSION_RECIPIENT_MESSAGE, BOB_KEY_MATERIAL, SHARED_BYTES);
  }

  @Test
  public void repeatDevicesAreNotDiagnosed() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "03",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0111aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2 (Alice device #3)
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Recipient 3 (also Alice device #3)
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0333ff",
            ALICE_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 1);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa),
          new Pair<>((byte) 0x03, (short) 0x33aa),
          new Pair<>((byte) 0x03, (short) 0x33ff),
        });
    assertMessageForRecipient(
        message, alice, VERSION_RECIPIENT_MESSAGE, ALICE_KEY_MATERIAL, SHARED_BYTES);
  }

  @Test
  public void serviceIdsWithCompactDeviceList() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "02",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0111aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2
            PNI_MARKER,
            BOB_UUID_BYTES,
            "0191bb", // high bit in registration ID flags another device
            "0333bb",
            BOB_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 2);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa),
        });
    assertMessageForRecipient(
        message, alice, VERSION_RECIPIENT_MESSAGE, ALICE_KEY_MATERIAL, SHARED_BYTES);

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(
                ServiceId.parseFromBinary(
                    Hex.fromStringsCondensedAssert(PNI_MARKER, BOB_UUID_BYTES)));
    assertNotNull(bob);
    assertArrayEquals(
        bob.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11bb), new Pair<>((byte) 0x03, (short) 0x33bb),
        });
    assertMessageForRecipient(
        message, bob, VERSION_RECIPIENT_MESSAGE, BOB_KEY_MATERIAL, SHARED_BYTES);
  }

  @Test
  public void serviceIdsWithCompactDeviceListAndRepeatedRecipient() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "03",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0191aa", // high bit in registration ID flags another device
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2
            PNI_MARKER,
            BOB_UUID_BYTES,
            "0111bb",
            BOB_KEY_MATERIAL,
            // Recipient 3 (note that it's another device of Alice's)
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0505aa",
            ALICE_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 2);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa),
          new Pair<>((byte) 0x03, (short) 0x33aa),
          new Pair<>((byte) 0x05, (short) 0x05aa),
        });
    assertMessageForRecipient(
        message, alice, VERSION_RECIPIENT_MESSAGE, ALICE_KEY_MATERIAL, SHARED_BYTES);

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(
                ServiceId.parseFromBinary(
                    Hex.fromStringsCondensedAssert(PNI_MARKER, BOB_UUID_BYTES)));
    assertNotNull(bob);
    assertArrayEquals(
        bob.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11bb),
        });
    assertMessageForRecipient(
        message, bob, VERSION_RECIPIENT_MESSAGE, BOB_KEY_MATERIAL, SHARED_BYTES);
  }

  @Test
  public void serviceIdsWithExcludedRecipients() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "04",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0191aa", // high bit in registration ID flags another device
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2: excluded by device ID 0
            ACI_MARKER,
            EVE_UUID_BYTES,
            "00",
            // Recipient 3
            PNI_MARKER,
            BOB_UUID_BYTES,
            "0111bb",
            BOB_KEY_MATERIAL,
            // Recipient 4 (also excluded)
            ACI_MARKER,
            MALLORY_UUID_BYTES,
            "00",
            // Shared data
            SHARED_BYTES);

    SealedSenderMultiRecipientMessage message = SealedSenderMultiRecipientMessage.parse(input);
    assertEquals(message.getRecipients().size(), 2);

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    assertArrayEquals(
        alice.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11aa), new Pair<>((byte) 0x03, (short) 0x33aa),
        });
    assertMessageForRecipient(
        message, alice, VERSION_RECIPIENT_MESSAGE, ALICE_KEY_MATERIAL, SHARED_BYTES);

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(
                ServiceId.parseFromBinary(
                    Hex.fromStringsCondensedAssert(PNI_MARKER, BOB_UUID_BYTES)));
    assertNotNull(bob);
    assertArrayEquals(
        bob.getDevicesAndRegistrationIds().toArray(),
        new Pair[] {
          new Pair<>((byte) 0x01, (short) 0x11bb),
        });
    assertMessageForRecipient(
        message, bob, VERSION_RECIPIENT_MESSAGE, BOB_KEY_MATERIAL, SHARED_BYTES);

    assertEquals(
        message.getExcludedRecipients(),
        Arrays.asList(
            ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(EVE_UUID_BYTES)),
            ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(MALLORY_UUID_BYTES))));
  }

  @Test
  public void rejectsRepeatedExcludedRecipients() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "03",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0191aa", // high bit in registration ID flags another device
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2: excluded by device ID 0
            ACI_MARKER,
            EVE_UUID_BYTES,
            "00",
            // Recipient 3 (same as #2)
            ACI_MARKER,
            EVE_UUID_BYTES,
            "00",
            // Shared data
            SHARED_BYTES);

    assertThrows(
        InvalidMessageException.class, () -> SealedSenderMultiRecipientMessage.parse(input));
  }

  @Test
  public void rejectsExcludedAfterRegular() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "02",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0191aa", // high bit in registration ID flags another device
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2: excluded by device ID 0
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "00",
            // Shared data
            SHARED_BYTES);

    assertThrows(
        InvalidMessageException.class, () -> SealedSenderMultiRecipientMessage.parse(input));
  }

  @Test
  public void rejectsRegularAfterExcluded() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "02",
            // Recipient 1: excluded by device ID 0
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "00",
            // Recipient 2: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0191aa", // high bit in registration ID flags another device
            "0333aa",
            ALICE_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    assertThrows(
        InvalidMessageException.class, () -> SealedSenderMultiRecipientMessage.parse(input));
  }

  @Test
  public void rejectsDeviceIdZeroInMultiDeviceList() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_SERVICE_ID_AWARE,
            // Count
            "01",
            // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
            ACI_MARKER,
            ALICE_UUID_BYTES,
            "0191aa", // high bit in registration ID flags another device
            "00",
            ALICE_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    assertThrows(
        InvalidMessageException.class, () -> SealedSenderMultiRecipientMessage.parse(input));
  }

  @Test
  public void rejectsUnknownVersions() throws Exception {
    assertThrows(
        InvalidVersionException.class,
        () -> SealedSenderMultiRecipientMessage.parse(new byte[] {0x11}));
    assertThrows(
        InvalidVersionException.class,
        () -> SealedSenderMultiRecipientMessage.parse(new byte[] {0x2F}));
    assertThrows(
        InvalidVersionException.class,
        () -> SealedSenderMultiRecipientMessage.parse(new byte[] {0x77}));
  }

  @Test
  public void wayTooManyRecipients() throws Exception {
    var count = 25000;
    var zeros = new byte[48];
    var oneDeviceEntry = Hex.fromStringCondensedAssert("0111aa");

    var input = new ByteArrayOutputStream();
    input.write(Hex.fromStringCondensedAssert(VERSION_ACI_ONLY));
    input.write(Hex.fromStringCondensedAssert("a8c301")); // echo 25000 | protoscope -s | xxd
    for (int i = 0; i < count; ++i) {
      input.write(zeros, 0, 14);
      input.write(i & 0xFF);
      input.write((i >> 8) & 0xFF);

      input.write(oneDeviceEntry);
      input.write(zeros, 0, 48);
    }
    input.write(zeros);

    var message = SealedSenderMultiRecipientMessage.parse(input.toByteArray());
    assertEquals(message.getRecipients().size(), count);
  }

  @Test
  public void wayTooManyExcludedRecipients() throws Exception {
    var count = 25000;
    var zeros = new byte[48];

    var input = new ByteArrayOutputStream();
    input.write(Hex.fromStringCondensedAssert(VERSION_ACI_ONLY));
    input.write(Hex.fromStringCondensedAssert("a8c301")); // echo 25000 | protoscope -s | xxd
    for (int i = 0; i < count; ++i) {
      input.write(zeros, 0, 14);
      input.write(i & 0xFF);
      input.write((i >> 8) & 0xFF);

      input.write(0);
    }
    input.write(zeros);

    var message = SealedSenderMultiRecipientMessage.parse(input.toByteArray());
    assertEquals(message.getExcludedRecipients().size(), count);
  }

  @Test
  public void recipientMessageView() throws Exception {
    byte[] input =
        Hex.fromStringsCondensedAssert(
            VERSION_ACI_ONLY,
            // Count
            "03",
            // Recipient 1: UUID, Device ID and Registration ID, Key Material
            ALICE_UUID_BYTES,
            "0111aa",
            ALICE_KEY_MATERIAL,
            // Recipient 2
            BOB_UUID_BYTES,
            "0111bb",
            BOB_KEY_MATERIAL,
            // Recipient 3 (note that it's another device of Bob's)
            BOB_UUID_BYTES,
            "0333bb",
            BOB_KEY_MATERIAL,
            // Shared data
            SHARED_BYTES);

    final SealedSenderMultiRecipientMessage message =
        SealedSenderMultiRecipientMessage.parse(input);

    int sharedDataOffset = input.length - SHARED_BYTES.length() / 2;

    SealedSenderMultiRecipientMessage.Recipient alice =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(ALICE_UUID_BYTES)));
    assertNotNull(alice);
    int aliceKeyMaterialOffset = 2 + 3 + ALICE_UUID_BYTES.length() / 2;
    int keyMaterialLength = 48;
    assertArrayEquals(
        ByteBuffer.allocate(13)
            .put((byte) 0x01)
            .putInt(sharedDataOffset)
            .putInt(aliceKeyMaterialOffset)
            .putInt(keyMaterialLength)
            .array(),
        message.serializedRecipientView(alice));

    SealedSenderMultiRecipientMessage.Recipient bob =
        message
            .getRecipients()
            .get(ServiceId.parseFromBinary(Hex.fromStringCondensedAssert(BOB_UUID_BYTES)));
    assertNotNull(bob);
    int bobKeyMaterialOffset =
        aliceKeyMaterialOffset + keyMaterialLength + BOB_UUID_BYTES.length() / 2 + 3;
    assertArrayEquals(
        ByteBuffer.allocate(13)
            .put((byte) 0x01)
            .putInt(sharedDataOffset)
            .putInt(bobKeyMaterialOffset)
            .putInt(keyMaterialLength)
            .array(),
        message.serializedRecipientView(bob));
  }

  @Test
  public void rejectsInvalidRecipientViews() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> SealedSenderMultiRecipientMessage.messageForRecipient(new byte[0], new byte[0]));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SealedSenderMultiRecipientMessage.messageForRecipient(
                new byte[0], ByteBuffer.allocate(14).put((byte) 0x01).array()));

    final ByteBuffer buffer = ByteBuffer.allocate(13);
    assertThrows(
        InvalidVersionException.class,
        () -> SealedSenderMultiRecipientMessage.messageForRecipient(new byte[0], buffer.array()));
    assertThrows(
        InvalidVersionException.class,
        () ->
            SealedSenderMultiRecipientMessage.messageForRecipient(
                new byte[0], buffer.clear().put((byte) 0x02).array()));
    assertThrows(
        InvalidVersionException.class,
        () ->
            SealedSenderMultiRecipientMessage.messageForRecipient(
                new byte[0], buffer.clear().put((byte) 0x2F).array()));
    assertThrows(
        InvalidVersionException.class,
        () ->
            SealedSenderMultiRecipientMessage.messageForRecipient(
                new byte[0], buffer.clear().put((byte) 0x77).array()));
  }
}
