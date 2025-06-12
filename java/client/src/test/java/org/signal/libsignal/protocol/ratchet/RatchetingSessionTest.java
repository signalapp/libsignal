//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.ratchet;

import java.util.Arrays;
import junit.framework.TestCase;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.SessionRecordTest;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPrivateKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.util.Hex;

public class RatchetingSessionTest extends TestCase {

  public void testRatchetingSessionAsBob() throws InvalidKeyException {
    byte[] bobPublic =
        Hex.fromStringCondensedAssert(
            "052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458");

    byte[] bobPrivate =
        Hex.fromStringCondensedAssert(
            "a1cab48f7c893fafa9880a28c3b4999d28d6329562d27a4ea4e22e9ff1bdd65a");

    byte[] bobIdentityPublic =
        Hex.fromStringCondensedAssert(
            "05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626");

    byte[] bobIdentityPrivate =
        Hex.fromStringCondensedAssert(
            "4875cc69ddf8ea0719ec947d61081135868d5fd801f02c0225e516df2156605e");

    byte[] aliceBasePublic =
        Hex.fromStringCondensedAssert(
            "05e2c05860f2ac6b2b57ba564b421ffe71e4b128c591e46e0491cc9b33dbf22a27");

    byte[] aliceIdentityPublic =
        Hex.fromStringCondensedAssert(
            "05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a");

    byte[] bobSignedPreKeyPublic =
        Hex.fromStringCondensedAssert(
            "05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67");

    byte[] bobSignedPreKeyPrivate =
        Hex.fromStringCondensedAssert(
            "583900131fb727998b7803fe6ac22cc591f342e4e42a8c8d5d78194209b8d253");

    byte[] senderChain =
        Hex.fromStringCondensedAssert(
            "ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a");

    IdentityKey bobIdentityKeyPublic = new IdentityKey(bobIdentityPublic, 0);
    ECPrivateKey bobIdentityKeyPrivate = new ECPrivateKey(bobIdentityPrivate);
    IdentityKeyPair bobIdentityKey =
        new IdentityKeyPair(bobIdentityKeyPublic, bobIdentityKeyPrivate);
    ECPublicKey bobEphemeralPublicKey = new ECPublicKey(bobPublic, 0);
    ECPrivateKey bobEphemeralPrivateKey = new ECPrivateKey(bobPrivate);
    ECKeyPair bobEphemeralKey = new ECKeyPair(bobEphemeralPublicKey, bobEphemeralPrivateKey);
    ECKeyPair bobBaseKey = bobEphemeralKey;
    ECKeyPair bobSignedPreKey =
        new ECKeyPair(
            new ECPublicKey(bobSignedPreKeyPublic, 0), new ECPrivateKey(bobSignedPreKeyPrivate));

    ECPublicKey aliceBasePublicKey = new ECPublicKey(aliceBasePublic, 0);
    IdentityKey aliceIdentityPublicKey = new IdentityKey(aliceIdentityPublic, 0);

    SessionRecord session =
        SessionRecordTest.initializeBobSession(
            bobIdentityKey,
            bobSignedPreKey,
            bobEphemeralKey,
            aliceIdentityPublicKey,
            aliceBasePublicKey);

    assertTrue(session.getLocalIdentityKey().equals(bobIdentityKey.getPublicKey()));
    assertTrue(session.getRemoteIdentityKey().equals(aliceIdentityPublicKey));
    assertTrue(Arrays.equals(SessionRecordTest.getSenderChainKeyValue(session), senderChain));
  }

  public void testRatchetingSessionAsAlice() throws InvalidKeyException {
    byte[] bobPublic =
        Hex.fromStringCondensedAssert(
            "052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458");

    byte[] bobIdentityPublic =
        Hex.fromStringCondensedAssert(
            "05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626");

    byte[] bobSignedPreKeyPublic =
        Hex.fromStringCondensedAssert(
            "05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67");

    byte[] aliceBasePublic =
        Hex.fromStringCondensedAssert(
            "05e2c05860f2ac6b2b57ba564b421ffe71e4b128c591e46e0491cc9b33dbf22a27");

    byte[] aliceBasePrivate =
        Hex.fromStringCondensedAssert(
            "10ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449");

    byte[] aliceEphemeralPublic =
        Hex.fromStringCondensedAssert(
            "056c3e0d1f520283efcc55fca5e67075b904007f1881d151af76df18c51d29d34b");

    byte[] aliceEphemeralPrivate =
        Hex.fromStringCondensedAssert(
            "d1ba38cea91743d33939c33c84986509280161b8b60fc7870c599c1d46201248");

    byte[] aliceIdentityPublic =
        Hex.fromStringCondensedAssert(
            "05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a");

    byte[] aliceIdentityPrivate =
        Hex.fromStringCondensedAssert(
            "9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58");

    byte[] receiverChain =
        Hex.fromStringCondensedAssert(
            "ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a");

    IdentityKey bobIdentityKey = new IdentityKey(bobIdentityPublic, 0);
    ECPublicKey bobEphemeralPublicKey = new ECPublicKey(bobPublic, 0);
    ECPublicKey bobSignedPreKey = new ECPublicKey(bobSignedPreKeyPublic, 0);
    ECPublicKey aliceBasePublicKey = new ECPublicKey(aliceBasePublic, 0);
    ECPrivateKey aliceBasePrivateKey = new ECPrivateKey(aliceBasePrivate);
    ECKeyPair aliceBaseKey = new ECKeyPair(aliceBasePublicKey, aliceBasePrivateKey);
    ECPublicKey aliceEphemeralPublicKey = new ECPublicKey(aliceEphemeralPublic, 0);
    ECPrivateKey aliceEphemeralPrivateKey = new ECPrivateKey(aliceEphemeralPrivate);
    ECKeyPair aliceEphemeralKey = new ECKeyPair(aliceEphemeralPublicKey, aliceEphemeralPrivateKey);
    IdentityKey aliceIdentityPublicKey = new IdentityKey(aliceIdentityPublic, 0);
    ECPrivateKey aliceIdentityPrivateKey = new ECPrivateKey(aliceIdentityPrivate);
    IdentityKeyPair aliceIdentityKey =
        new IdentityKeyPair(aliceIdentityPublicKey, aliceIdentityPrivateKey);

    SessionRecord session =
        SessionRecordTest.initializeAliceSession(
            aliceIdentityKey, aliceBaseKey, bobIdentityKey, bobSignedPreKey, bobEphemeralPublicKey);

    assertTrue(session.getLocalIdentityKey().equals(aliceIdentityKey.getPublicKey()));
    assertTrue(session.getRemoteIdentityKey().equals(bobIdentityKey));
    assertTrue(
        Arrays.equals(
            SessionRecordTest.getReceiverChainKeyValue(session, bobEphemeralPublicKey),
            receiverChain));
  }
}
