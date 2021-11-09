//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

const UINT64_MAX = BigInt('0xFFFFFFFFFFFFFFFF');

export function bufferFromBigUInt64BE(value: bigint): Buffer {
  if (value < 0 || value > UINT64_MAX) {
    throw new RangeError(`value ${value} isn't representable as a u64`);
  }
  const result = Buffer.alloc(8);
  result.writeBigUInt64BE(value);
  return result;
}
