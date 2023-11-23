//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

public class UntrustedIdentityException extends Exception {

  private final String name;
  private final IdentityKey key;

  public UntrustedIdentityException(String name, IdentityKey key) {
    this.name = name;
    this.key = key;
  }

  public UntrustedIdentityException(String name) {
    this.name = name;
    this.key = null;
  }

  public IdentityKey getUntrustedIdentity() {
    return key;
  }

  public String getName() {
    return name;
  }
}
