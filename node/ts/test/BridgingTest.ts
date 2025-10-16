//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as uuid from 'uuid';
import { assert, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import * as Native from '../Native.js';
import { BridgedStringMap } from '../internal.js';

use(chaiAsPromised);

function makeAsyncRuntime(): Native.Wrapper<Native.NonSuspendingBackgroundThreadRuntime> {
  return {
    _nativeHandle: Native.TESTING_NonSuspendingBackgroundThreadRuntime_New(),
  };
}

describe('bridge_fn', () => {
  it('handles errors in argument conversion', () => {
    assert.throws(() => Native.TESTING_ErrorOnBorrowSync(null), TypeError);

    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    assert.throws(() => Native.TESTING_ErrorOnBorrowAsync(null), TypeError);

    const runtime = makeAsyncRuntime();
    assert.throws(
      // eslint-disable-next-line @typescript-eslint/no-misused-promises
      () => Native.TESTING_ErrorOnBorrowIo(runtime, null),
      TypeError
    );
  });

  it('handles panics in argument conversion', () => {
    assert.throws(() => Native.TESTING_PanicOnBorrowSync(null), Error);

    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    assert.throws(() => Native.TESTING_PanicOnBorrowAsync(null), Error);

    const runtime = makeAsyncRuntime();
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    assert.throws(() => Native.TESTING_PanicOnBorrowIo(runtime, null), Error);
  });

  it('handles panics in argument loading', async () => {
    assert.throws(() => Native.TESTING_PanicOnLoadSync(null, null), Error);

    await assert.isRejected(Native.TESTING_PanicOnLoadAsync(null, null), Error);

    const runtime = makeAsyncRuntime();
    await assert.isRejected(
      Native.TESTING_PanicOnLoadIo(runtime, null, null),
      Error
    );
  });

  it('handles panics in the function body', async () => {
    assert.throws(() => Native.TESTING_PanicInBodySync(null), Error);

    await assert.isRejected(Native.TESTING_PanicInBodyAsync(null), Error);

    const runtime = makeAsyncRuntime();
    await assert.isRejected(Native.TESTING_PanicInBodyIo(runtime, null), Error);
  });

  it('handles errors in returning', async () => {
    assert.throws(() => Native.TESTING_ErrorOnReturnSync(null), TypeError);

    await assert.isRejected(Native.TESTING_ErrorOnReturnAsync(null), TypeError);

    const runtime = makeAsyncRuntime();
    await assert.isRejected(
      Native.TESTING_ErrorOnReturnIo(runtime, null),
      TypeError
    );
  });

  it('handles panics in returning', async () => {
    assert.throws(() => Native.TESTING_PanicOnReturnSync(null), Error);

    await assert.isRejected(Native.TESTING_PanicOnReturnAsync(null), Error);

    const runtime = makeAsyncRuntime();
    await assert.isRejected(
      Native.TESTING_PanicOnReturnIo(runtime, null),
      Error
    );
  });

  it('can take string arrays', () => {
    assert.deepStrictEqual(
      Native.TESTING_JoinStringArray(['a', 'b', 'c'], ' - '),
      'a - b - c'
    );
  });

  it('can return string arrays', () => {
    assert.deepStrictEqual(Native.TESTING_ReturnStringArray(), [
      'easy',
      'as',
      'ABC',
      '123',
    ]);
  });

  it('can process bytestring arrays', () => {
    const result = Native.TESTING_ProcessBytestringArray([
      Uint8Array.of(1, 2, 3),
      Uint8Array.of(),
      Uint8Array.of(4, 5, 6),
    ]);
    assert.deepStrictEqual(
      result.map((buffer) => Array.from(buffer)),
      [[1, 2, 3, 1, 2, 3], [], [4, 5, 6, 4, 5, 6]]
    );
  });

  it('can process empty bytestring arrays', () => {
    assert.deepStrictEqual(Native.TESTING_ProcessBytestringArray([]), []);
  });

  it('can round-trip various kinds of numbers', () => {
    for (const value of [0, 1, 0x7f, 0x80, 0xff]) {
      assert.strictEqual(value, Native.TESTING_RoundTripU8(value));
    }
    for (const value of [
      -1,
      0x100,
      Number.MAX_SAFE_INTEGER,
      Number.MAX_VALUE,
      Number.POSITIVE_INFINITY,
      Number.NaN,
    ]) {
      assert.throws(() => Native.TESTING_RoundTripU8(value));
    }

    for (const value of [0, 1, 0x7fff, 0x8000, 0xffff]) {
      assert.strictEqual(value, Native.TESTING_RoundTripU16(value));
    }
    for (const value of [
      -1,
      0x1_0000,
      Number.MAX_SAFE_INTEGER,
      Number.MAX_VALUE,
      Number.POSITIVE_INFINITY,
      Number.NaN,
    ]) {
      assert.throws(() => Native.TESTING_RoundTripU16(value));
    }

    for (const value of [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff]) {
      assert.strictEqual(value, Native.TESTING_RoundTripU32(value));
    }
    for (const value of [
      -1,
      0x1_0000_0000,
      Number.MAX_SAFE_INTEGER,
      Number.MAX_VALUE,
      Number.POSITIVE_INFINITY,
      Number.NaN,
    ]) {
      assert.throws(() => Native.TESTING_RoundTripU32(value));
    }

    for (const value of [0, 1, 0x7fff_ffff, -0x8000_0000, -1]) {
      assert.strictEqual(value, Native.TESTING_RoundTripI32(value));
    }
    for (const value of [
      0x1_0000_0000,
      -0x1_0000_0000,
      Number.MAX_SAFE_INTEGER,
      Number.MAX_VALUE,
      Number.POSITIVE_INFINITY,
      Number.NaN,
    ]) {
      assert.throws(() => Native.TESTING_RoundTripI32(value));
    }

    for (const value of [
      0n,
      1n,
      0x7fff_ffff_ffff_ffffn,
      0x8000_0000_0000_0000n,
      0xffff_ffff_ffff_ffffn,
    ]) {
      assert.strictEqual(value, Native.TESTING_RoundTripU64(value));
    }
    for (const value of [-1n, 0x1_0000_0000_0000_0000n]) {
      assert.throws(() => Native.TESTING_RoundTripU64(value));
    }
  });

  it('can convert optional UUID values', () => {
    const present = Native.TESTING_ConvertOptionalUuid(true);
    assert.deepEqual(
      present,
      uuid.parse('abababab-1212-8989-baba-565656565656')
    );

    const absent = Native.TESTING_ConvertOptionalUuid(false);
    assert.isNull(absent);
  });

  it('can return pairs', () => {
    const [num, str] = Native.TESTING_ReturnPair();
    assert.equal(num, 1);
    assert.equal(str, 'libsignal');
  });
});

describe('BridgedStringMap', () => {
  it('can round-trip', () => {
    const empty = new BridgedStringMap(new Map()).dump();
    assert.equal(empty, '{}');

    const dumped = new BridgedStringMap(
      new Map([
        ['b', 'bbb'],
        ['a', 'aaa'],
        ['c', 'ccc'],
      ])
    ).dump();
    assert.equal(
      dumped,
      `\
{
  "a": "aaa",
  "b": "bbb",
  "c": "ccc"
}`
    );
  });
});
