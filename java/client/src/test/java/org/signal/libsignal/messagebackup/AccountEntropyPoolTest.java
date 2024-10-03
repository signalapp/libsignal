//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.Test;

public class AccountEntropyPoolTest {
  @Test
  public void accountEntropyStringMeetsSpecifications() {
    int numIterations = 100;
    Set<String> generatedEntropyPools = new HashSet<>();

    for (int i = 0; i < numIterations; i++) {
      String pool = AccountEntropyPool.generate();
      assertTrue("Pool contains invalid characters: " + pool, pool.matches("[a-z0-9]+"));
      assertTrue("Duplicate pool generated: " + pool, generatedEntropyPools.add(pool));
    }
  }
}
