//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.junit.Test;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.Hex;

public class SessionRecordTest {

  public static byte[] getAliceBaseKey(SessionRecord record) {
    return filterExceptions(
        () -> record.guardedMapChecked(NativeTesting::SessionRecord_GetAliceBaseKey));
  }

  public static byte[] getReceiverChainKeyValue(SessionRecord record, ECPublicKey senderEphemeral) {
    try (NativeHandleGuard guard = new NativeHandleGuard(record);
        NativeHandleGuard ephemeralGuard = new NativeHandleGuard(senderEphemeral); ) {
      return filterExceptions(
          () ->
              NativeTesting.SessionRecord_GetReceiverChainKeyValue(
                  guard.nativeHandle(), ephemeralGuard.nativeHandle()));
    }
  }

  public static byte[] getSenderChainKeyValue(SessionRecord record) {
    return filterExceptions(
        () -> record.guardedMapChecked(NativeTesting::SessionRecord_GetSenderChainKeyValue));
  }

  public static SessionRecord initializeAliceSession(
      IdentityKeyPair identityKey,
      ECKeyPair baseKey,
      IdentityKey theirIdentityKey,
      ECPublicKey theirSignedPreKey,
      ECPublicKey theirRatchetKey) {
    try (NativeHandleGuard identityPrivateGuard =
            new NativeHandleGuard(identityKey.getPrivateKey());
        NativeHandleGuard identityPublicGuard =
            new NativeHandleGuard(identityKey.getPublicKey().getPublicKey());
        NativeHandleGuard basePrivateGuard = new NativeHandleGuard(baseKey.getPrivateKey());
        NativeHandleGuard basePublicGuard = new NativeHandleGuard(baseKey.getPublicKey());
        NativeHandleGuard theirIdentityGuard =
            new NativeHandleGuard(theirIdentityKey.getPublicKey());
        NativeHandleGuard theirSignedPreKeyGuard = new NativeHandleGuard(theirSignedPreKey);
        NativeHandleGuard theirRatchetKeyGuard = new NativeHandleGuard(theirRatchetKey); ) {
      return new SessionRecord(
          filterExceptions(
              () ->
                  NativeTesting.SessionRecord_InitializeAliceSession(
                      identityPrivateGuard.nativeHandle(),
                      identityPublicGuard.nativeHandle(),
                      basePrivateGuard.nativeHandle(),
                      basePublicGuard.nativeHandle(),
                      theirIdentityGuard.nativeHandle(),
                      theirSignedPreKeyGuard.nativeHandle(),
                      theirRatchetKeyGuard.nativeHandle())));
    } catch (InvalidMessageException m) {
      throw new RuntimeException(m);
    }
  }

  public static SessionRecord initializeBobSession(
      IdentityKeyPair identityKey,
      ECKeyPair signedPreKey,
      ECKeyPair ephemeralKey,
      IdentityKey theirIdentityKey,
      ECPublicKey theirBaseKey) {
    try (NativeHandleGuard identityPrivateGuard =
            new NativeHandleGuard(identityKey.getPrivateKey());
        NativeHandleGuard identityPublicGuard =
            new NativeHandleGuard(identityKey.getPublicKey().getPublicKey());
        NativeHandleGuard signedPreKeyPrivateGuard =
            new NativeHandleGuard(signedPreKey.getPrivateKey());
        NativeHandleGuard signedPreKeyPublicGuard =
            new NativeHandleGuard(signedPreKey.getPublicKey());
        NativeHandleGuard ephemeralPrivateGuard =
            new NativeHandleGuard(ephemeralKey.getPrivateKey());
        NativeHandleGuard ephemeralPublicGuard =
            new NativeHandleGuard(ephemeralKey.getPublicKey());
        NativeHandleGuard theirIdentityGuard =
            new NativeHandleGuard(theirIdentityKey.getPublicKey());
        NativeHandleGuard theirBaseKeyGuard = new NativeHandleGuard(theirBaseKey); ) {
      return new SessionRecord(
          filterExceptions(
              () ->
                  NativeTesting.SessionRecord_InitializeBobSession(
                      identityPrivateGuard.nativeHandle(),
                      identityPublicGuard.nativeHandle(),
                      signedPreKeyPrivateGuard.nativeHandle(),
                      signedPreKeyPublicGuard.nativeHandle(),
                      ephemeralPrivateGuard.nativeHandle(),
                      ephemeralPublicGuard.nativeHandle(),
                      theirIdentityGuard.nativeHandle(),
                      theirBaseKeyGuard.nativeHandle())));
    } catch (InvalidMessageException m) {
      throw new RuntimeException(m);
    }
  }

  @Test
  public void testUninitAccess() {
    SessionRecord empty_record = new SessionRecord();

    assertFalse(empty_record.hasSenderChain());

    assertEquals(empty_record.getSessionVersion(), 0);
  }

  @Test
  public void testBadPreKeyRecords() throws Exception {
    assertThrows(InvalidMessageException.class, () -> new PreKeyRecord(new byte[] {0}));
    assertThrows(InvalidMessageException.class, () -> new SignedPreKeyRecord(new byte[] {0}));
    assertThrows(InvalidMessageException.class, () -> new KyberPreKeyRecord(new byte[] {0}));

    // The keys in records are lazily parsed, which means malformed keys aren't caught right away.
    // The following payloads were generated via protoscope:
    // % protoscope -s | xxd -p
    // The fields are described in storage.proto in the libsignal-protocol crate.
    {
      // 1: 42
      // 2: {}
      // 3: {}
      final var record = new PreKeyRecord(Hex.fromStringCondensedAssert("082a12001a00"));
      assertThrows(InvalidKeyException.class, () -> record.getKeyPair());
    }

    {
      // 1: 42
      // 2: {}
      // 3: {}
      // 4: {}
      // 5: 0i64
      final var record =
          new SignedPreKeyRecord(
              Hex.fromStringCondensedAssert("082a12001a002200290000000000000000"));
      assertThrows(InvalidKeyException.class, () -> record.getKeyPair());
    }

    {
      // 1: 42
      // 2: {}
      // 3: {}
      // 4: {}
      // 5: 0i64
      final var record =
          new KyberPreKeyRecord(
              Hex.fromStringCondensedAssert("082a12001a002200290000000000000000"));
      assertThrows(InvalidKeyException.class, () -> record.getKeyPair());
    }
  }
}
