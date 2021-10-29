//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Ideally we would replace the operations in this file with the 'uuid' package,
// but the tests use an invalid UUID as a test string, and 'uuid' always validates.

export type UUIDType = string;

export function toUUID(array: Buffer): UUIDType {
  const hex = array.toString('hex');
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(
    12,
    16
  )}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

export function fromUUID(uuid: UUIDType): Buffer {
  let i = 0;
  const array = Buffer.alloc(16);

  uuid.replace(/[0-9A-F]{2}/gi, (oct: string): string => {
    array[i++] = parseInt(oct, 16);
    return '';
  });

  return array;
}
