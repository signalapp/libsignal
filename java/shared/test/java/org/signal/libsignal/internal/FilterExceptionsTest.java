//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import org.junit.Test;
import org.signal.libsignal.internal.FilterExceptions.ThrowingNativeVoidOperation;

public class FilterExceptionsTest {

  private static class UnexpectedException extends Exception {
    public UnexpectedException(String message) {
      super(message);
    }
  }

  @Test
  public void exceptionTextIncludesClass() {
    AssertionError error =
        assertThrows(
            AssertionError.class,
            () -> {
              filterExceptions(
                  (ThrowingNativeVoidOperation)
                      () -> {
                        throw new UnexpectedException("not expected");
                      });
            });

    assertThat(error.getMessage(), containsString("FilterExceptionsTest$UnexpectedException"));
  }
}
