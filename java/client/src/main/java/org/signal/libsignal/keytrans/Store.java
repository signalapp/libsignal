//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import java.nio.ByteBuffer;
import java.util.Optional;
import org.signal.libsignal.protocol.ServiceId;

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
 *
 * <p>Note: depending on the usage of {@link org.signal.libsignal.net.KeyTransparencyClient} APIs,
 * {@code Store} methods may be invoked from multiple threads.
 */
public interface Store {
  Optional<byte[]> getLastDistinguishedTreeHead();

  void setLastDistinguishedTreeHead(byte[] lastDistinguishedTreeHead);

  Optional<byte[]> getAccountData(ServiceId.Aci aci);

  void setAccountData(ServiceId.Aci aci, byte[] data);

  default void applyUpdates(ServiceId.Aci aci, SearchResult searchResult) {
    searchResult.updateStore(aci, this);
  }
}
