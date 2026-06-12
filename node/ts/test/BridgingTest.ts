//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import * as Native from '../Native.js';
import * as NativeNice from '../NativeNice.js';
import { BridgedStringMap } from '../internal.js';
import * as uuid from '../uuid.js';
import { Aci, Pni } from '../Address.js';
import { toBase64 } from './util.js';
import { TokioAsyncContext } from '../net.js';

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

  it('handles BridgeHandleRef', () => {
    const handle = Native.TESTING_TestingIntBox_New(17);
    assert.equal(
      Native.TESTING_TestingIntBox_Get({ _nativeHandle: handle }),
      17
    );
    assert.equal(
      NativeNice.TESTING_TestingIntBox_Get({
        myIntBox: { _nativeHandle: handle },
      }),
      17
    );
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

describe('NativeTestingNice', () => {
  const asyncContext = new TokioAsyncContext(Native.TokioAsyncContext_new());
  async function testConversion<T>({
    item,
    toString,
    nativeToString,
    nativeIdentity,
    nativeIdentityAsync,
  }: {
    item: T;
    toString: string;
    nativeToString: (t: T) => string;
    nativeIdentity: (t: T) => T;
    nativeIdentityAsync: (args: {
      asyncContext: TokioAsyncContext;
      x: T;
    }) => Promise<T>;
  }) {
    assert.strictEqual(toString, nativeToString(item));
    assert.deepEqual(item, nativeIdentity(item));
    assert.deepEqual(
      item,
      await nativeIdentityAsync({ asyncContext, x: item })
    );
  }
  it('string', async () => {
    for (const item of ['', 'abc', 'îüéè']) {
      await testConversion({
        item,
        toString: item,
        nativeToString: (x) =>
          NativeNice.TESTING_conversion_string_identity({ x }),
        nativeIdentity: (x) =>
          NativeNice.TESTING_conversion_string_identity({ x }),
        nativeIdentityAsync:
          NativeNice.TESTING_conversion_string_identity_async,
      });
    }
  });
  it('bool', async () => {
    for (const item of [true, false]) {
      await testConversion({
        item,
        toString: `${item}`,
        nativeToString: (x) =>
          NativeNice.TESTING_conversion_bool_to_string({ x }),
        nativeIdentity: (x) =>
          NativeNice.TESTING_conversion_bool_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_conversion_bool_identity_async,
      });
    }
  });
  it('u8', async () => {
    for (let item = 0; item <= 255; item++) {
      await testConversion({
        item,
        toString: `${item}`,
        nativeToString: (x) =>
          NativeNice.TESTING_conversion_u8_to_string({ x }),
        nativeIdentity: (x) => NativeNice.TESTING_conversion_u8_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_conversion_u8_identity_async,
      });
    }
  });
  it('u16', async () => {
    for (let item = 0; item <= 1024; item++) {
      await testConversion({
        item,
        toString: `${item}`,
        nativeToString: (x) =>
          NativeNice.TESTING_conversion_u16_to_string({ x }),
        nativeIdentity: (x) =>
          NativeNice.TESTING_conversion_u16_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_conversion_u16_identity_async,
      });
    }
  });
  it('i32', async () => {
    for (let item = -1024; item <= 1024; item++) {
      await testConversion({
        item,
        toString: `${item}`,
        nativeToString: (x) =>
          NativeNice.TESTING_conversion_i32_to_string({ x }),
        nativeIdentity: (x) =>
          NativeNice.TESTING_conversion_i32_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_conversion_i32_identity_async,
      });
    }
  });
  it('ServiceId', async () => {
    for (let i = 0; i <= 4; i++) {
      for (const item of [
        Aci.fromUuid(uuid.stringify(uuid.v4())),
        Pni.fromUuid(uuid.stringify(uuid.v4())),
      ]) {
        await testConversion({
          item,
          toString: item.getServiceIdString(),
          nativeToString: (x) =>
            NativeNice.TESTING_conversion_ServiceId_to_string({ x }),
          nativeIdentity: (x) =>
            NativeNice.TESTING_conversion_ServiceId_identity({ x }),
          nativeIdentityAsync:
            NativeNice.TESTING_conversion_ServiceId_identity_async,
        });
      }
    }
  });
  it('Data', async () => {
    for (let i = 0; i < 10; i++) {
      const item = crypto.getRandomValues(new Uint8Array(1 << i));
      await testConversion({
        item,
        toString: toBase64(item),
        nativeToString: (x) =>
          NativeNice.TESTING_conversion_Data_to_string({ x }),
        nativeIdentity: (x) =>
          NativeNice.TESTING_conversion_Data_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_conversion_Data_identity_async,
      });
      await testConversion({
        item,
        toString: toBase64(item),
        nativeToString: (x) =>
          NativeNice.TESTING_conversion_Data_VecU8_to_string({ x }),
        nativeIdentity: (x) =>
          NativeNice.TESTING_conversion_Data_VecU8_identity({ x }),
        nativeIdentityAsync:
          NativeNice.TESTING_conversion_Data_VecU8_identity_async,
      });
    }
  });
  it('should handle async', async () => {
    for (const count of [0, 1, 2, 4, 8, 16, 32, 64, 128, 256]) {
      const data =
        await NativeNice.TESTING_TokioAsyncContext_FutureSuccessBytes({
          asyncContext,
          count,
        });
      assert.equal(data.length, count);
    }
  });

  it('derived conversions', async () => {
    {
      for (const item of ['a', 'b'] as const) {
        await testConversion({
          item,
          toString: item.toUpperCase(),
          nativeToString: (x) =>
            NativeNice.TESTING_MySimpleTestEnum_to_string({ x }),
          nativeIdentity: (x) =>
            NativeNice.TESTING_MySimpleTestEnum_identity({ x }),
          nativeIdentityAsync:
            NativeNice.TESTING_MySimpleTestEnum_identity_async,
        });
      }
    }
    {
      const item: NativeNice.MyTestPoint = [1, 2];
      await testConversion({
        item,
        toString: JSON.stringify(item),
        nativeToString: (x) => NativeNice.TESTING_MyTestPoint_to_string({ x }),
        nativeIdentity: (x) => NativeNice.TESTING_MyTestPoint_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_MyTestPoint_identity_async,
      });
    }
    {
      const item: NativeNice.MyTestStruct = {
        myNumericField: 47,
        myStringField: 'hello!',
      };
      await testConversion({
        item,
        toString: JSON.stringify(item),
        nativeToString: (x) => NativeNice.TESTING_MyTestStruct_to_string({ x }),
        nativeIdentity: (x) => NativeNice.TESTING_MyTestStruct_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_MyTestStruct_identity_async,
      });
    }
    const testEnums: NativeNice.MyTestEnum[] = [
      'unit',
      { single: 123 },
      { double: [7483, 7832] },
      {
        record: {
          personName: 'Person!',
          personAge: 102,
          position: [8, 9],
          funStruct: {
            myNumericField: 748,
            myStringField: 'strings!!',
          },
        },
      },
    ];
    for (const item of testEnums) {
      await testConversion({
        item,
        toString: JSON.stringify(item),
        nativeToString: (x) => NativeNice.TESTING_MyTestEnum_to_string({ x }),
        nativeIdentity: (x) => NativeNice.TESTING_MyTestEnum_identity({ x }),
        nativeIdentityAsync: NativeNice.TESTING_MyTestEnum_identity_async,
      });
    }
    // We manually test this variant because we don't expose the name of the single variant in
    // our bridge, while serde does in its JSON representation
    await testConversion({
      item: { singleNamed: 456 },
      toString: JSON.stringify({ singleNamed: { x: 456 } }),
      nativeToString: (x) => NativeNice.TESTING_MyTestEnum_to_string({ x }),
      nativeIdentity: (x) => NativeNice.TESTING_MyTestEnum_identity({ x }),
      nativeIdentityAsync: NativeNice.TESTING_MyTestEnum_identity_async,
    });
  });
});
