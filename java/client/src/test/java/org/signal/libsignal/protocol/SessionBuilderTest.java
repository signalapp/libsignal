package org.signal.libsignal.protocol;

import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.PreKeySignalMessage;
import org.signal.libsignal.protocol.message.SignalMessage;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.Medium;
import org.signal.libsignal.protocol.util.Pair;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.experimental.runners.Enclosed;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


@RunWith(Enclosed.class)
public class SessionBuilderTest {
  private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
  private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("+14152222222", 1);

  @RunWith(Parameterized.class)
  public static class Versioned {
    private final BundleFactory bundleFactory;
    private int expectedVersion;

    public Versioned(BundleFactory bundleFactory, int expectedVersion) {
      this.bundleFactory = bundleFactory;
      this.expectedVersion = expectedVersion;
    }

    @Parameters(name = "v{1}")
    public static Collection<Object[]> data() throws Exception {
      return Arrays.asList(new Object[][] {
        {new X3DHBundleFactory(), 3},
        {new PQXDHBundleFactory(), 4}
      });
    }

    @Test
    public void testBasicPreKey()
        throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, UntrustedIdentityException, NoSessionException {
      SignalProtocolStore aliceStore     = new TestInMemorySignalProtocolStore();
      SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

      final SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

      PreKeyBundle bobPreKey = bundleFactory.createBundle(bobStore);

      aliceSessionBuilder.process(bobPreKey);

      assertTrue(aliceStore.containsSession(BOB_ADDRESS));
      assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionVersion() == expectedVersion);

      String            originalMessage    = "Good, fast, cheap: pick two";
      SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
      CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

      assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

      PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());

      SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
      byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);

      assertTrue(bobStore.containsSession(ALICE_ADDRESS));
      assertEquals(bobStore.loadSession(ALICE_ADDRESS).getSessionVersion(), expectedVersion);
      assertNotNull(bobStore.loadSession(ALICE_ADDRESS).getAliceBaseKey());
      assertTrue(originalMessage.equals(new String(plaintext)));

      CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
      assertTrue(bobOutgoingMessage.getType() == CiphertextMessage.WHISPER_TYPE);

      byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
      assertTrue(new String(alicePlaintext).equals(originalMessage));

      runInteraction(aliceStore, bobStore);

      aliceStore          = new TestInMemorySignalProtocolStore();
      aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
      aliceSessionCipher  = new SessionCipher(aliceStore, BOB_ADDRESS);

      PreKeyBundle anotherBundle = bundleFactory.createBundle(bobStore);
      aliceSessionBuilder.process(anotherBundle);

      outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

      try {
        plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
        fail("shouldn't be trusted!");
      } catch (UntrustedIdentityException uie) {
        bobStore.saveIdentity(ALICE_ADDRESS, new PreKeySignalMessage(outgoingMessage.serialize()).getIdentityKey());
      }

      plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
      assertTrue(new String(plaintext).equals(originalMessage));

      Random random = new Random();
      PreKeyBundle badIdentityBundle = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                                                        random.nextInt(Medium.MAX_VALUE), Curve.generateKeyPair().getPublicKey(),
                                                        random.nextInt(Medium.MAX_VALUE), bobPreKey.getSignedPreKey(), bobPreKey.getSignedPreKeySignature(),
                                                        aliceStore.getIdentityKeyPair().getPublicKey());

      try {
        aliceSessionBuilder.process(badIdentityBundle);
        fail("shoulnd't be trusted!");
      } catch (UntrustedIdentityException uie) {
        // good
      }
    }

    @Test
    public void testRepeatBundleMessage() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
      SignalProtocolStore aliceStore     = new TestInMemorySignalProtocolStore();
      SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

      SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

      PreKeyBundle bobPreKey = bundleFactory.createBundle(bobStore);
      aliceSessionBuilder.process(bobPreKey);

      String            originalMessage    = "Good, fast, cheap: pick two";
      SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
      CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());
      CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(originalMessage.getBytes());

      assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);
      assertTrue(outgoingMessageTwo.getType() == CiphertextMessage.PREKEY_TYPE);

      PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());

      SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

      byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);
      assertTrue(originalMessage.equals(new String(plaintext)));

      CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

      byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
      assertTrue(originalMessage.equals(new String(alicePlaintext)));

      // The test

      PreKeySignalMessage incomingMessageTwo = new PreKeySignalMessage(outgoingMessageTwo.serialize());

      plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(incomingMessageTwo.serialize()));
      assertTrue(originalMessage.equals(new String(plaintext)));

      bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
      alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
      assertTrue(originalMessage.equals(new String(alicePlaintext)));
    }

    @Test
    public void testOptionalOneTimePreKey() throws Exception {
      SignalProtocolStore aliceStore     = new TestInMemorySignalProtocolStore();
      SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

      SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();
      PreKeyBundle bobPreKey       = bundleFactory.createBundle(bobStore);

      // Simply remove the pre-key information from a valid bundle
      bobPreKey = new PreKeyBundle(bobPreKey.getRegistrationId(), 1,
          -1, null,
          bobPreKey.getSignedPreKeyId(), bobPreKey.getSignedPreKey(), bobPreKey.getSignedPreKeySignature(),
          bobPreKey.getIdentityKey(),
          bobPreKey.getKyberPreKeyId(), bobPreKey.getKyberPreKey(), bobPreKey.getKyberPreKeySignature());

      aliceSessionBuilder.process(bobPreKey);

      assertTrue(aliceStore.containsSession(BOB_ADDRESS));
      assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionVersion() == expectedVersion);

      String            originalMessage    = "Good, fast, cheap: pick two";
      SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
      CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

      assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

      PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
      assertTrue(!incomingMessage.getPreKeyId().isPresent());

      SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
      byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);

      assertTrue(bobStore.containsSession(ALICE_ADDRESS));
      assertEquals(bobStore.loadSession(ALICE_ADDRESS).getSessionVersion(), expectedVersion);
      assertNotNull(bobStore.loadSession(ALICE_ADDRESS).getAliceBaseKey());
      assertEquals(originalMessage, new String(plaintext));
    }
  }


  public static class VersionAgnostic {

    @Test
    public void testBadSignedPreKeySignature() throws InvalidKeyException, UntrustedIdentityException {
      SignalProtocolStore aliceStore     = new TestInMemorySignalProtocolStore();
      SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

      IdentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

      ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
      ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
      byte[]    bobSignedPreKeySignature = Curve.calculateSignature(
                                             bobIdentityKeyStore.getIdentityKeyPair().getPrivateKey(),
                                             bobSignedPreKeyPair.getPublicKey().serialize());


      for (int i=0;i<bobSignedPreKeySignature.length * 8;i++) {
        byte[] modifiedSignature = new byte[bobSignedPreKeySignature.length];
        System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

        modifiedSignature[i/8] ^= (0x01 << (i % 8));

        PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
            31337, bobPreKeyPair.getPublicKey(),
            22, bobSignedPreKeyPair.getPublicKey(), modifiedSignature,
            bobIdentityKeyStore.getIdentityKeyPair().getPublicKey(),
            -1, null, new byte[0]);

        try {
          aliceSessionBuilder.process(bobPreKey);
          fail("Accepted modified device key signature!");
        } catch (InvalidKeyException ike) {
          // good
        }
      }

      PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
          31337, bobPreKeyPair.getPublicKey(),
          22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
          bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

      aliceSessionBuilder.process(bobPreKey);
    }


    @Test
    public void testBadMessageBundle() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException, InvalidKeyIdException {
      SignalProtocolStore aliceStore     = new TestInMemorySignalProtocolStore();
      SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

      SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();
      BundleFactory bundleFactory  = new PQXDHBundleFactory();
      PreKeyBundle bobPreKey       = bundleFactory.createBundle(bobStore);

      aliceSessionBuilder.process(bobPreKey);

      String            originalMessage    = "Good, fast, cheap: pick two";
      SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
      CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

      assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

      byte[] goodMessage = outgoingMessageOne.serialize();
      byte[] badMessage  = new byte[goodMessage.length];
      System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

      badMessage[badMessage.length-10] ^= 0x01;

      PreKeySignalMessage incomingMessage  = new PreKeySignalMessage(badMessage);
      SessionCipher        bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

      byte[] plaintext = new byte[0];

      try {
        plaintext = bobSessionCipher.decrypt(incomingMessage);
        fail("Decrypt should have failed!");
      } catch (InvalidMessageException e) {
        // good.
      }

      assertTrue(bobStore.containsPreKey(bobPreKey.getPreKeyId()));

      plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(goodMessage));

      assertTrue(originalMessage.equals(new String(plaintext)));
      assertFalse(bobStore.containsPreKey(bobPreKey.getPreKeyId()));
    }

    @Test
    public void testBadSignedPreKeyStore() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException {
      SignalProtocolStore aliceStore = new TestNoSignedPreKeysStore();
      SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

      SignalProtocolStore bobStore = new TestNoSignedPreKeysStore();
      BundleFactory bundleFactory  = new PQXDHBundleFactory();
      PreKeyBundle bobPreKey       = bundleFactory.createBundle(bobStore);

      aliceSessionBuilder.process(bobPreKey);

      String            originalMessage    = "Good, fast, cheap: pick two";
      SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
      CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

      assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

      PreKeySignalMessage incomingMessage  = new PreKeySignalMessage(outgoingMessageOne.serialize());
      SessionCipher       bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

      try {
        bobSessionCipher.decrypt(incomingMessage);
        fail("Decrypt should have failed!");
      } catch (InvalidKeyIdException e) {
        assertEquals("TestNoSignedPreKeysStore rejected loading " + bobPreKey.getSignedPreKeyId(), e.getMessage());
      }
    }

    @Test
    public void testBadSignedPreKeyStoreError() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException {
      SignalProtocolStore aliceStore = new TestBadSignedPreKeysStore();
      SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

      SignalProtocolStore bobStore = new TestBadSignedPreKeysStore();
      BundleFactory bundleFactory  = new PQXDHBundleFactory();
      PreKeyBundle bobPreKey       = bundleFactory.createBundle(bobStore);

      aliceSessionBuilder.process(bobPreKey);

      String            originalMessage    = "Good, fast, cheap: pick two";
      SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
      CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

      assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

      PreKeySignalMessage incomingMessage  = new PreKeySignalMessage(outgoingMessageOne.serialize());
      SessionCipher        bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

      try {
        bobSessionCipher.decrypt(incomingMessage);
        fail("Decrypt should have failed!");
      } catch (InvalidKeyIdException e) {
        fail("libsignal swallowed the exception");
      } catch (TestBadSignedPreKeysStore.CustomException e) {
        // success!
      }
    }
  }

  private static void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, InvalidVersionException, InvalidKeyException, NoSessionException, UntrustedIdentityException
  {
    SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    SessionCipher bobSessionCipher   = new SessionCipher(bobStore, ALICE_ADDRESS);

    String originalMessage = "smert ze smert";
    CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertEquals(aliceMessage.getType(), CiphertextMessage.WHISPER_TYPE);

    byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceMessage.serialize()));
    assertTrue(new String(plaintext).equals(originalMessage));

    CiphertextMessage bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

    assertEquals(bobMessage.getType(), CiphertextMessage.WHISPER_TYPE);

    plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobMessage.serialize()));
    assertTrue(new String(plaintext).equals(originalMessage));

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    Set<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
    }

    for (int i=0;i<10;i++) {
      String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                               "We mean that man first of all exists, encounters himself, " +
                               "surges up in the world--and defines himself aftward. " + i);
      CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (int i=0;i<10;i++) {
      String loopingMessage = ("You can only desire based on what you know: " + i);
      CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

      byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
      assertTrue(new String(loopingPlaintext).equals(loopingMessage));
    }

    for (Pair<String, CiphertextMessage> aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
      byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceOutOfOrderMessage.second().serialize()));
      assertTrue(new String(outOfOrderPlaintext).equals(aliceOutOfOrderMessage.first()));
    }
  }

}
