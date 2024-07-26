//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import java.util.List;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.protocol.InvalidKeyIdException;

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
   * <p>Remove if it is a one-time pre key and noop if it is last-resort.
   *
   * @param kyberPreKeyId The ID of the KyberPreKeyRecord to marked.
   */
  public void markKyberPreKeyUsed(int kyberPreKeyId);
}
