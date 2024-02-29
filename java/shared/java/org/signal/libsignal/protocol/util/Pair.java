//
// Copyright 2014-2016 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.util;

import java.util.Objects;

public class Pair<T1, T2> {
  private final T1 v1;
  private final T2 v2;

  public Pair(T1 v1, T2 v2) {
    this.v1 = v1;
    this.v2 = v2;
  }

  public T1 first() {
    return v1;
  }

  public T2 second() {
    return v2;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof Pair
        && Objects.equals(((Pair) o).first(), first())
        && Objects.equals(((Pair) o).second(), second());
  }

  @Override
  public int hashCode() {
    return Objects.hash(first(), second());
  }

  @Override
  public String toString() {
    // Useful for debugging, matches the description used by Apache Commons' Pair.
    return "(" + first() + "," + second() + ")";
  }
}
