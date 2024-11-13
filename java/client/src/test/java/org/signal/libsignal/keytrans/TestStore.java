//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Optional;

public class TestStore implements Store {

  public HashMap<ByteBuffer, byte[]> storage = new HashMap<>();
  public byte[] lastTreeHead;
  public byte[] lastDistinguishedTreeHead;

  @Override
  public Optional<byte[]> getLastTreeHead() {
    return Optional.ofNullable(lastTreeHead);
  }

  @Override
  public void setLastTreeHead(byte[] lastTreeHead) {
    this.lastTreeHead = lastTreeHead;
  }

  @Override
  public Optional<byte[]> getLastDistinguishedTreeHead() {
    return Optional.ofNullable(lastDistinguishedTreeHead);
  }

  @Override
  public void setLastDistinguishedTreeHead(byte[] lastDistinguishedTreeHead) {
    this.lastDistinguishedTreeHead = lastDistinguishedTreeHead;
  }

  @Override
  public Optional<byte[]> getMonitorData(ByteBuffer searchKey) {
    return Optional.ofNullable(this.storage.get(searchKey));
  }

  @Override
  public void setMonitorData(ByteBuffer searchKey, byte[] monitorData) {
    this.storage.put(searchKey, monitorData);
  }
}
