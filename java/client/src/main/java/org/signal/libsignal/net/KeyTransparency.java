//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

public abstract class KeyTransparency {
  /**
   * Mode of the monitor operation.
   *
   * <p>If the newer version of account data is found in the key transparency log, self-monitor will
   * terminate with an error, but monitor for other account will fall back to a full search and
   * update the locally stored data.
   */
  public enum MonitorMode {
    SELF,
    OTHER
  }
}
