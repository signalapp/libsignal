//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Interface of a local persistent key transparency data store.
 *
 * <p>Contents of the store are opaque to the client and are only supposed to be used by the {@link
 * org.signal.libsignal.net.KeyTransparencyClient}.
 *
 * <p>{@link ByteBuffer} is used for the keys because of its hashing semantics. Alternative default
 * implementations accepting byte arrays are provided for convenience.
 *
 * <p>It is safe to assume that {@code null} will never be passed to any of the parameters.
 */
public interface Store {
  Optional<byte[]> getLastTreeHead();

  void setLastTreeHead(byte[] lastTreeHead);

  Optional<byte[]> getLastDistinguishedTreeHead();

  void setLastDistinguishedTreeHead(byte[] lastDistinguishedTreeHead);

  Optional<byte[]> getMonitorData(ByteBuffer searchKey);

  void setMonitorData(ByteBuffer searchKey, byte[] monitorData);

  default Optional<byte[]> getMonitorData(byte[] searchKey) {
    return getMonitorData(searchKey == null ? null : ByteBuffer.wrap(searchKey));
  }

  default void setMonitorData(byte[] searchKey, byte[] monitorData) {
    setMonitorData(ByteBuffer.wrap(searchKey), monitorData);
  }

  default void applyUpdates(SearchResult searchResult) {
    searchResult.updateStore(this);
  }
}
