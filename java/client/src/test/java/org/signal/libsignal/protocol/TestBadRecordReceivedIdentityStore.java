//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

public class TestBadRecordReceivedIdentityStore extends TestInMemorySignalProtocolStore {
  public static class CustomException extends RuntimeException {
    CustomException(String message) {
      super(message);
    }
  }

  @Override
  public void recordReceivedIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    throw new CustomException("TestBadRecordReceivedIdentityStore rejected " + address);
  }
}
