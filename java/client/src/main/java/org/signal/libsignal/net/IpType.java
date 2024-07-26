//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

/** The order of values in this enum should match {@code IpType} enum in Rust (libsignal-net). */
public enum IpType {
  UNKNOWN,
  IPv4,
  IPv6
}
