//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.state;

import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.protocol.InvalidKeyIdException;

/**
 * An interface describing the local storage of {@link PreKeyRecord}s.
 *
 * @author Moxie Marlinspike
 */
@CalledFromNative
public interface PreKeyStore {

  /**
   * Load a local PreKeyRecord.
   *
   * @param preKeyId the ID of the local PreKeyRecord.
   * @return the corresponding PreKeyRecord.
   * @throws InvalidKeyIdException when there is no corresponding PreKeyRecord.
   */
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException;

  /**
   * Store a local PreKeyRecord.
   *
   * @param preKeyId the ID of the PreKeyRecord to store.
   * @param record the PreKeyRecord.
   */
  public void storePreKey(int preKeyId, PreKeyRecord record);

  /**
   * @param preKeyId A PreKeyRecord ID.
   * @return true if the store has a record for the preKeyId, otherwise false.
   */
  public boolean containsPreKey(int preKeyId);

  /**
   * Delete a PreKeyRecord from local storage.
   *
   * @param preKeyId The ID of the PreKeyRecord to remove.
   */
  public void removePreKey(int preKeyId);
}
