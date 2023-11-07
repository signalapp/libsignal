//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.protocol.util.Pair;

public class SealedSenderMultiRecipientMessageTest {
  static final String VERSION_ACI_ONLY = "22";
  static final String VERSION_SERVICE_ID_AWARE = "23";

  static final String ACI_MARKER = "00";
  static final String PNI_MARKER = "01";

  static final String ALICE_UUID_BYTES = "9d0652a3dcc34d11975f74d61598733f";
  static final String ALICE_KEY_MATERIAL =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  static final String BOB_UUID_BYTES = "e80f7bbe5b94471ebd8c2173654ea3d1";
  static final String BOB_KEY_MATERIAL =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  static final String SHARED_BYTES =
      "99999999999999999999999999999999999999999999999999999999999999999999";

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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_ACI_ONLY, ALICE_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(alice));

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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_ACI_ONLY, BOB_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(bob));
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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_ACI_ONLY, ALICE_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(alice));

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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_ACI_ONLY, BOB_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(bob));
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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, ALICE_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(alice));

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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, BOB_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(bob));
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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, ALICE_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(alice));

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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, BOB_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(bob));
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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, ALICE_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(alice));

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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, BOB_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(bob));
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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, ALICE_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(alice));

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
    assertArrayEquals(
        Hex.fromStringsCondensedAssert(VERSION_SERVICE_ID_AWARE, BOB_KEY_MATERIAL, SHARED_BYTES),
        message.messageForRecipient(bob));
  }
}
