//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.internal;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import kotlin.Pair;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

public class BridgingTest {
  long ioRuntime = 0;

  @Before
  public void initIoRuntime() {
    ioRuntime = NativeTesting.TESTING_NonSuspendingBackgroundThreadRuntime_New();
  }

  @After
  public void destroyIoRuntime() {
    NativeTesting.TESTING_NonSuspendingBackgroundThreadRuntime_Destroy(ioRuntime);
    ioRuntime = 0;
  }

  @Test
  public void testErrorOnBorrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class, () -> NativeTesting.TESTING_ErrorOnBorrowSync(null));
    assertThrows(
        IllegalArgumentException.class, () -> NativeTesting.TESTING_ErrorOnBorrowAsync(null));
    assertThrows(
        IllegalArgumentException.class,
        () -> NativeTesting.TESTING_ErrorOnBorrowIo(ioRuntime, null).get());
  }

  @Test
  public void testPanicOnBorrow() throws Exception {
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicOnBorrowSync(null));
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicOnBorrowAsync(null));
    assertThrows(
        AssertionError.class, () -> NativeTesting.TESTING_PanicOnBorrowIo(ioRuntime, null).get());
  }

  @Test
  public void testPanicOnLoad() throws Exception {
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicOnLoadSync(null, null));
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicOnLoadAsync(null, null));
    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> NativeTesting.TESTING_PanicOnLoadIo(ioRuntime, null, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof AssertionError);
  }

  @Test
  public void testPanicInBody() throws Exception {
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicInBodySync(null));
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicInBodyAsync(null));
    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> NativeTesting.TESTING_PanicInBodyIo(ioRuntime, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof AssertionError);
  }

  @Test
  public void testErrorOnReturn() throws Exception {
    assertThrows(
        IllegalArgumentException.class, () -> NativeTesting.TESTING_ErrorOnReturnSync(null));
    assertThrows(
        IllegalArgumentException.class, () -> NativeTesting.TESTING_ErrorOnReturnAsync(null));
    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> NativeTesting.TESTING_ErrorOnReturnIo(ioRuntime, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof IllegalArgumentException);
  }

  @Test
  public void testPanicOnReturn() throws Exception {
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicOnReturnSync(null));
    assertThrows(AssertionError.class, () -> NativeTesting.TESTING_PanicOnReturnAsync(null));
    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> NativeTesting.TESTING_PanicOnReturnIo(ioRuntime, null).get());
    assertTrue(e.getCause().toString(), e.getCause() instanceof AssertionError);
  }

  @Test
  public void testTakeStringArrayAsArg() {
    assertEquals(
        NativeTesting.TESTING_JoinStringArray(new String[] {"a", "b", "c"}, " - "), "a - b - c");
  }

  @Test
  public void testReturnStringArray() {
    assertArrayEquals(
        NativeTesting.TESTING_ReturnStringArray(), new String[] {"easy", "as", "ABC", "123"});
  }

  @Test
  public void testProcessBytestringArray() {
    ByteBuffer first = ByteBuffer.allocateDirect(3);
    first.put(new byte[] {1, 2, 3});
    ByteBuffer empty = ByteBuffer.allocateDirect(0);
    ByteBuffer second = ByteBuffer.allocateDirect(3);
    second.put(new byte[] {4, 5, 6});
    byte[][] result =
        NativeTesting.TESTING_ProcessBytestringArray(new ByteBuffer[] {first, empty, second});
    assertArrayEquals(result, new byte[][] {{1, 2, 3, 1, 2, 3}, {}, {4, 5, 6, 4, 5, 6}});
  }

  @Test
  public void testProcessEmptyBytestringArray() {
    assertArrayEquals(
        NativeTesting.TESTING_ProcessBytestringArray(new ByteBuffer[] {}), new byte[][] {});
  }

  @Test
  public void testIntegerRoundTrips() {
    // Java doesn't have unsigned integers. We handle this differently for different types.

    // For u8, we pass values as int.
    for (var value : new int[] {0, 1, 0x7f, 0x80, 0xff}) {
      assertEquals(value, NativeTesting.TESTING_RoundTripU8(value));
    }
    for (var value : new int[] {0x100, -1, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
      assertThrows(IllegalArgumentException.class, () -> NativeTesting.TESTING_RoundTripU8(value));
    }

    // For u16, we pass values as int.
    for (var value : new int[] {0, 1, 0x7fff, 0x8000, 0xffff}) {
      assertEquals(value, NativeTesting.TESTING_RoundTripU16(value));
    }
    for (var value : new int[] {0x1_0000, -1, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
      assertThrows(IllegalArgumentException.class, () -> NativeTesting.TESTING_RoundTripU16(value));
    }

    // For u32, we only support passing positive values. (We actually support *returning* large
    // values by reinterpreting the bits, but this API can't test that.)
    for (var value : new int[] {0, 1, Integer.MAX_VALUE}) {
      assertEquals(value, NativeTesting.TESTING_RoundTripU32(value));
    }
    for (var value : new int[] {-1, Integer.MIN_VALUE}) {
      assertThrows(IllegalArgumentException.class, () -> NativeTesting.TESTING_RoundTripU32(value));
    }

    // And for u64, we reinterpret the bits, which means we can round trip but negative values are
    // treated as large positive ones.
    for (var value : new long[] {0, 1, -1, Long.MAX_VALUE, Long.MIN_VALUE}) {
      assertEquals(value, NativeTesting.TESTING_RoundTripU64(value));
    }

    // Signed integers we can handle directly.
    for (var value : new int[] {0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
      assertEquals(value, NativeTesting.TESTING_RoundTripI32(value));
    }
  }

  @Test
  public void testOptionalUuid() {
    final var present = NativeTesting.TESTING_ConvertOptionalUuid(true);
    assertEquals(present, UUID.fromString("abababab-1212-8989-baba-565656565656"));

    final var absent = NativeTesting.TESTING_ConvertOptionalUuid(false);
    assertNull(absent);
  }

  @Test
  public void testBridgedStringMap() {
    final var empty = new BridgedStringMap(Collections.emptyMap()).dump();
    assertEquals(empty, "{}");

    final var map = new HashMap<String, String>();
    map.put("b", "bbb");
    map.put("a", "aaa");
    map.put("c", "ccc");
    final var dumped = new BridgedStringMap(map).dump();
    assertEquals(
        dumped,
        """
      {
        "a": "aaa",
        "b": "bbb",
        "c": "ccc"
      }""");
  }

  @Test
  public void testTypeTagging() throws Exception {
    long handle = NativeTesting.TESTING_FutureProducesPointerType(ioRuntime, 5).get();
    try {
      // This 48 comes from TYPE_TAG_POINTER_OFFSET in Rust.
      // It would be more principled to expose that through a method,
      // but since this is just a test it's okay to hardcode it just once.
      Assume.assumeTrue("type tagging should be enabled", ((handle >> 48) & 0xFF) != 0);
      NativeTesting.TESTING_OtherTestingHandleType_getValue(handle);
      fail("should have panicked");
    } catch (AssertionError e) {
      // The "fail" is also an AssertionError, so we have to check the message.
      assertEquals(
          e.getMessage(),
          "bad parameter type libsignal_bridge_testing::convert::OtherTestingHandleType");
    } finally {
      NativeTesting.TestingHandleType_Destroy(handle);
    }
  }

  @Test
  public void testReturnPair() throws Exception {
    var pair = NativeTesting.TESTING_ReturnPair();
    assertEquals(pair, new Pair<>(1, "libsignal"));
  }
}
