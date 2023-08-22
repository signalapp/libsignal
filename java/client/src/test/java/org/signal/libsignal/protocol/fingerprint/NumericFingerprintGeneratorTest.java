//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.fingerprint;

import java.util.Arrays;
import junit.framework.TestCase;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.util.Hex;

public class NumericFingerprintGeneratorTest extends TestCase {

  private static final byte[] ALICE_IDENTITY =
      Hex.fromStringCondensedAssert(
          "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868");
  private static final byte[] BOB_IDENTITY =
      Hex.fromStringCondensedAssert(
          "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b");
  private static final int VERSION_1 = 1;
  private static final String DISPLAYABLE_FINGERPRINT_V1 =
      "300354477692869396892869876765458257569162576843440918079131";
  private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V1 =
      Hex.fromStringCondensedAssert(
          "080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d");
  private static final byte[] BOB_SCANNABLE_FINGERPRINT_V1 =
      Hex.fromStringCondensedAssert(
          "080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df");
  private static final int VERSION_2 = 2;
  private static final String DISPLAYABLE_FINGERPRINT_V2 = DISPLAYABLE_FINGERPRINT_V1;
  private static final byte[] ALICE_SCANNABLE_FINGERPRINT_V2 =
      Hex.fromStringCondensedAssert(
          "080212220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d");
  private static final byte[] BOB_SCANNABLE_FINGERPRINT_V2 =
      Hex.fromStringCondensedAssert(
          "080212220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df");

  public void testVectorsVersion1() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey = new IdentityKey(BOB_IDENTITY, 0);
    byte[] aliceStableId = "+14152222222".getBytes();
    byte[] bobStableId = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprint =
        generator.createFor(
            VERSION_1, aliceStableId, aliceIdentityKey, bobStableId, bobIdentityKey);

    Fingerprint bobFingerprint =
        generator.createFor(
            VERSION_1, bobStableId, bobIdentityKey, aliceStableId, aliceIdentityKey);

    assertEquals(
        aliceFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V1);
    assertEquals(
        bobFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V1);

    assertTrue(
        Arrays.equals(
            aliceFingerprint.getScannableFingerprint().getSerialized(),
            ALICE_SCANNABLE_FINGERPRINT_V1));
    assertTrue(
        Arrays.equals(
            bobFingerprint.getScannableFingerprint().getSerialized(),
            BOB_SCANNABLE_FINGERPRINT_V1));
  }

  public void testVectorsVersion2() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey = new IdentityKey(BOB_IDENTITY, 0);
    byte[] aliceStableId = "+14152222222".getBytes();
    byte[] bobStableId = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprint =
        generator.createFor(
            VERSION_2, aliceStableId, aliceIdentityKey, bobStableId, bobIdentityKey);

    Fingerprint bobFingerprint =
        generator.createFor(
            VERSION_2, bobStableId, bobIdentityKey, aliceStableId, aliceIdentityKey);

    assertEquals(
        aliceFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V2);
    assertEquals(
        bobFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT_V2);

    assertTrue(
        Arrays.equals(
            aliceFingerprint.getScannableFingerprint().getSerialized(),
            ALICE_SCANNABLE_FINGERPRINT_V2));
    assertTrue(
        Arrays.equals(
            bobFingerprint.getScannableFingerprint().getSerialized(),
            BOB_SCANNABLE_FINGERPRINT_V2));
  }

  public void testMatchingFingerprints()
      throws FingerprintVersionMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
    Fingerprint aliceFingerprint =
        generator.createFor(
            VERSION_1,
            "+14152222222".getBytes(),
            aliceIdentityKey,
            "+14153333333".getBytes(),
            bobIdentityKey);

    Fingerprint bobFingerprint =
        generator.createFor(
            VERSION_1,
            "+14153333333".getBytes(),
            bobIdentityKey,
            "+14152222222".getBytes(),
            aliceIdentityKey);

    assertEquals(
        aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
        bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertTrue(
        aliceFingerprint
            .getScannableFingerprint()
            .compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertTrue(
        bobFingerprint
            .getScannableFingerprint()
            .compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText().length(), 60);
  }

  public void testMismatchingFingerprints()
      throws FingerprintVersionMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair = Curve.generateKeyPair();
    ECKeyPair mitmKeyPair = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());
    IdentityKey mitmIdentityKey = new IdentityKey(mitmKeyPair.getPublicKey());

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
    Fingerprint aliceFingerprint =
        generator.createFor(
            VERSION_1,
            "+14152222222".getBytes(),
            aliceIdentityKey,
            "+14153333333".getBytes(),
            mitmIdentityKey);

    Fingerprint bobFingerprint =
        generator.createFor(
            VERSION_1,
            "+14153333333".getBytes(),
            bobIdentityKey,
            "+14152222222".getBytes(),
            aliceIdentityKey);

    assertFalse(
        aliceFingerprint
            .getDisplayableFingerprint()
            .getDisplayText()
            .equals(bobFingerprint.getDisplayableFingerprint().getDisplayText()));

    assertFalse(
        aliceFingerprint
            .getScannableFingerprint()
            .compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(
        bobFingerprint
            .getScannableFingerprint()
            .compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testMismatchingIdentifiers()
      throws FingerprintVersionMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.getPublicKey());

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
    Fingerprint aliceFingerprint =
        generator.createFor(
            VERSION_1,
            "+141512222222".getBytes(),
            aliceIdentityKey,
            "+14153333333".getBytes(),
            bobIdentityKey);

    Fingerprint bobFingerprint =
        generator.createFor(
            VERSION_1,
            "+14153333333".getBytes(),
            bobIdentityKey,
            "+14152222222".getBytes(),
            aliceIdentityKey);

    assertFalse(
        aliceFingerprint
            .getDisplayableFingerprint()
            .getDisplayText()
            .equals(bobFingerprint.getDisplayableFingerprint().getDisplayText()));

    assertFalse(
        aliceFingerprint
            .getScannableFingerprint()
            .compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(
        bobFingerprint
            .getScannableFingerprint()
            .compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testDifferentVersionsMakeSameFingerPrintsButDifferentScannable() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey = new IdentityKey(BOB_IDENTITY, 0);
    byte[] aliceStableId = "+14152222222".getBytes();
    byte[] bobStableId = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprintV1 =
        generator.createFor(
            VERSION_1, aliceStableId, aliceIdentityKey, bobStableId, bobIdentityKey);

    Fingerprint aliceFingerprintV2 =
        generator.createFor(
            VERSION_2, aliceStableId, aliceIdentityKey, bobStableId, bobIdentityKey);

    assertTrue(
        aliceFingerprintV1
            .getDisplayableFingerprint()
            .getDisplayText()
            .equals(aliceFingerprintV2.getDisplayableFingerprint().getDisplayText()));

    assertFalse(
        Arrays.equals(
            aliceFingerprintV1.getScannableFingerprint().getSerialized(),
            aliceFingerprintV2.getScannableFingerprint().getSerialized()));
  }

  public void testDifferentVersionsThrowExpected() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey = new IdentityKey(BOB_IDENTITY, 0);
    byte[] aliceStableId = "+14152222222".getBytes();
    byte[] bobStableId = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprintV1 =
        generator.createFor(
            VERSION_1, aliceStableId, aliceIdentityKey, bobStableId, bobIdentityKey);

    Fingerprint bobFingerprintV2 =
        generator.createFor(
            VERSION_2, bobStableId, bobIdentityKey, aliceStableId, aliceIdentityKey);

    try {
      aliceFingerprintV1
          .getScannableFingerprint()
          .compareTo(bobFingerprintV2.getScannableFingerprint().getSerialized());
      throw new AssertionError("Should have thrown");
    } catch (FingerprintVersionMismatchException e) {
      assertEquals(e.getOurVersion(), 1);
      assertEquals(e.getTheirVersion(), 2);
    }

    try {
      bobFingerprintV2
          .getScannableFingerprint()
          .compareTo(aliceFingerprintV1.getScannableFingerprint().getSerialized());
      throw new AssertionError("Should have thrown");
    } catch (FingerprintVersionMismatchException e) {
      assertEquals(e.getOurVersion(), 2);
      assertEquals(e.getTheirVersion(), 1);
    }
  }

  public void testFingerprintParsingFail() throws Exception {
    IdentityKey aliceIdentityKey = new IdentityKey(ALICE_IDENTITY, 0);
    IdentityKey bobIdentityKey = new IdentityKey(BOB_IDENTITY, 0);
    byte[] aliceStableId = "+14152222222".getBytes();
    byte[] bobStableId = "+14153333333".getBytes();

    NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);

    Fingerprint aliceFingerprint =
        generator.createFor(
            VERSION_1, aliceStableId, aliceIdentityKey, bobStableId, bobIdentityKey);

    Fingerprint bobFingerprint =
        generator.createFor(
            VERSION_1, bobStableId, bobIdentityKey, aliceStableId, aliceIdentityKey);

    try {
      byte[] bobSer = bobFingerprint.getScannableFingerprint().getSerialized();
      bobSer[5] += 1;
      aliceFingerprint.getScannableFingerprint().compareTo(bobSer);
      throw new AssertionError("Should have thrown");
    } catch (FingerprintParsingException e) {
    }
  }
}
