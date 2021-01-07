//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.whispersystems.libsignal;

import junit.framework.TestCase;
import org.whispersystems.libsignal.state.SessionRecord;

public class SessionRecordTest extends TestCase {

  public void testUninitAccess() {
    SessionRecord empty_record = new SessionRecord();

    assertFalse(empty_record.hasSenderChain());

    assertEquals(empty_record.getSessionVersion(), 0);
  }
}
