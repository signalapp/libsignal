//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.util.Hex;

public class AccountEntropyPoolTest {
  @Test
  public void accountEntropyStringMeetsSpecifications() {
    int numIterations = 100;
    Set<String> generatedEntropyPools = new HashSet<>();

    for (int i = 0; i < numIterations; i++) {
      String pool = AccountEntropyPool.generate();
      assertTrue("Pool contains invalid characters: " + pool, pool.matches("[a-z0-9]+"));
      assertTrue("Duplicate pool generated: " + pool, generatedEntropyPools.add(pool));
    }
  }

  @Test
  public void testKeyDerivations() throws Exception {
    var pool = AccountEntropyPool.generate();

    var svrKey = AccountEntropyPool.deriveSvrKey(pool);
    assertEquals(32, svrKey.length);

    var backupKey = AccountEntropyPool.deriveBackupKey(pool);
    assertEquals(32, backupKey.serialize().length);

    var randomKey = BackupKey.generateRandom();
    assertNotEquals(backupKey, randomKey);

    var aci = new Aci(new UUID(0x1111111111111111L, 0x1111111111111111L));
    var otherAci = new Aci(UUID.randomUUID());

    var backupId = backupKey.deriveBackupId(aci);
    assertEquals(16, backupId.length);
    assertNotEquals(
        Hex.toStringCondensed(backupId), Hex.toStringCondensed(randomKey.deriveBackupId(aci)));
    assertNotEquals(
        Hex.toStringCondensed(backupId), Hex.toStringCondensed(backupKey.deriveBackupId(otherAci)));

    var ecKey = backupKey.deriveEcKey(aci);
    assertNotEquals(
        Hex.toStringCondensed(ecKey.serialize()),
        Hex.toStringCondensed(randomKey.deriveEcKey(aci).serialize()));
    assertNotEquals(
        Hex.toStringCondensed(ecKey.serialize()),
        Hex.toStringCondensed(backupKey.deriveEcKey(otherAci).serialize()));

    var localMetadataKey = backupKey.deriveLocalBackupMetadataKey();
    assertEquals(32, localMetadataKey.length);

    var mediaId = backupKey.deriveMediaId("example.jpg");
    assertEquals(15, mediaId.length);

    var mediaKey = backupKey.deriveMediaEncryptionKey(mediaId);
    assertEquals(32 + 32, mediaKey.length);

    assertThrows(
        "invalid media ID",
        IllegalArgumentException.class,
        () -> backupKey.deriveMediaEncryptionKey(new byte[1]));

    var thumbnailKey = backupKey.deriveThumbnailTransitEncryptionKey(mediaId);
    assertEquals(32 + 32, thumbnailKey.length);
    assertNotEquals(Hex.toStringCondensed(thumbnailKey), Hex.toStringCondensed(mediaKey));
  }
}
