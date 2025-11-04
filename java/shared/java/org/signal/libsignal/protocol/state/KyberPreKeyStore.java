//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import java.util.List;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.ReusedBaseKeyException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;

@CalledFromNative
public interface KyberPreKeyStore {

  /**
   * Load a local KyberPreKeyRecord.
   *
   * @param kyberPreKeyId the ID of the local KyberPreKeyRecord.
   * @return the corresponding KyberPreKeyRecord.
   * @throws InvalidKeyIdException when there is no corresponding KyberPreKeyRecord.
   */
  public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException;

  /**
   * Load all local KyberPreKeyRecords.
   *
   * @return All stored KyberPreKeyRecords.
   */
  public List<KyberPreKeyRecord> loadKyberPreKeys();

  /**
   * Store a local KyberPreKeyRecord.
   *
   * @param kyberPreKeyId the ID of the KyberPreKeyRecord to store.
   * @param record the KyberPreKeyRecord.
   */
  public void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record);

  /**
   * @param kyberPreKeyId A KyberPreKeyRecord ID.
   * @return true if the store has a record for the kyberPreKeyId, otherwise false.
   */
  public boolean containsKyberPreKey(int kyberPreKeyId);

  /**
   * Mark a KyberPreKeyRecord in the local storage as used.
   *
   * <p>If it's a one-time pre-key, remove it.
   *
   * <p>If it's a last-resort pre-key, check whether this specific <code>
   * (kyberPreKeyId, signedPreKeyId, baseKey)</code> tuple has been seen before, and throw an
   * exception if so. If not, record it for later. Entries can be removed when either the Kyber key
   * or the last-resort key is <strong>deleted</strong> (not just rotated).
   *
   * @param kyberPreKeyId The ID of the KyberPreKeyRecord to be marked.
   * @param signedPreKeyId The ID of the SignedPreKeyRecord that was used with this Kyber pre-key.
   * @param baseKey The session-specific key from the sender used with this Kyber pre-key.
   */
  public void markKyberPreKeyUsed(int kyberPreKeyId, int signedPreKeyId, ECPublicKey baseKey)
      throws ReusedBaseKeyException;
}
