//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import java.util.concurrent.ExecutionException;
import org.junit.Test;

public class BridgingTest {
  @Test
  public void testErrorOnBorrow() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> Native.TESTING_ErrorOnBorrowSync(null));
    assertThrows(IllegalArgumentException.class, () -> Native.TESTING_ErrorOnBorrowAsync(null));
    assertThrows(
        IllegalArgumentException.class, () -> Native.TESTING_ErrorOnBorrowIo(-1, null).get());
  }

  @Test
  public void testPanicOnBorrow() throws Exception {
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicOnBorrowSync(null));
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicOnBorrowAsync(null));
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicOnBorrowIo(-1, null).get());
  }

  @Test
  public void testPanicOnLoad() throws Exception {
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicOnLoadSync(null, null));
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicOnLoadAsync(null, null));
    ExecutionException e =
        assertThrows(
            ExecutionException.class, () -> Native.TESTING_PanicOnLoadIo(-1, null, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof AssertionError);
  }

  @Test
  public void testPanicInBody() throws Exception {
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicInBodySync(null));
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicInBodyAsync(null));
    ExecutionException e =
        assertThrows(ExecutionException.class, () -> Native.TESTING_PanicInBodyIo(-1, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof AssertionError);
  }

  @Test
  public void testErrorOnReturn() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> Native.TESTING_ErrorOnReturnSync(null));
    assertThrows(IllegalArgumentException.class, () -> Native.TESTING_ErrorOnReturnAsync(null));
    ExecutionException e =
        assertThrows(
            ExecutionException.class, () -> Native.TESTING_ErrorOnReturnIo(-1, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof IllegalArgumentException);
  }

  @Test
  public void testPanicOnReturn() throws Exception {
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicOnReturnSync(null));
    assertThrows(AssertionError.class, () -> Native.TESTING_PanicOnReturnAsync(null));
    ExecutionException e =
        assertThrows(
            ExecutionException.class, () -> Native.TESTING_PanicOnReturnIo(-1, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof AssertionError);
  }
}
