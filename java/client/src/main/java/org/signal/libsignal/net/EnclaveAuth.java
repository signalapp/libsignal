//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.util.Objects;

public class EnclaveAuth {
  String username;
  String password;

  public EnclaveAuth(String username, String password) {
    this.username = username;
    this.password = password;
  }

  public String getUsername() {
    return this.username;
  }

  public String getPassword() {
    return this.password;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }

    if (obj.getClass() != this.getClass()) {
      return false;
    }

    final EnclaveAuth other = (EnclaveAuth) obj;

    return Objects.equals(this.username, other.username)
        && Objects.equals(this.password, other.password);
  }
}
