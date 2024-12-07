//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import java.util.*;
import org.signal.libsignal.protocol.ServiceId;

public class TestStore implements Store {

  public HashMap<ServiceId.Aci, Deque<byte[]>> storage = new HashMap<>();
  public byte[] lastDistinguishedTreeHead;

  @Override
  public Optional<byte[]> getLastDistinguishedTreeHead() {
    return Optional.ofNullable(lastDistinguishedTreeHead);
  }

  @Override
  public void setLastDistinguishedTreeHead(byte[] lastDistinguishedTreeHead) {
    this.lastDistinguishedTreeHead = lastDistinguishedTreeHead;
  }

  @Override
  public Optional<byte[]> getAccountData(ServiceId.Aci aci) {
    Deque<byte[]> deque = this.storage.computeIfAbsent(aci, key -> new ArrayDeque<>());
    return Optional.ofNullable(deque.peekLast());
  }

  @Override
  public void setAccountData(ServiceId.Aci aci, byte[] data) {
    Deque<byte[]> deque = this.storage.computeIfAbsent(aci, key -> new ArrayDeque<>());
    deque.addLast(data);
  }
}
