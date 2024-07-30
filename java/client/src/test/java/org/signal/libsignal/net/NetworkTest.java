//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.junit.Test;

public class NetworkTest {
  private static final String USER_AGENT = "test";

  @Test
  public void networkChange() {
    // There's no feedback from this, we're just making sure it doesn't normally crash or throw.
    var net = new Network(Network.Environment.STAGING, USER_AGENT);
    net.onNetworkChange();
  }
}
