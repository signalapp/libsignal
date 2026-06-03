//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Shim for the `uuid` package on NPM, backed by Rust's `uuid` crate instead.
 * @module uuid
 */

import * as Native from './Native.js';

export type Uuid = string;

export const NIL = '00000000-0000-0000-0000-000000000000';

export function stringify(input: Uint8Array<ArrayBuffer>): string {
  return Native.uuid_to_string(input);
}

export function parse(input: string): Uint8Array<ArrayBuffer> {
  const result = Native.uuid_from_string(input);
  if (!result) {
    throw new TypeError(`invalid UUID: '${input}'`);
  }
  return result;
}

export function v4(): Uint8Array<ArrayBuffer> {
  return Native.uuid_new_v4();
}
