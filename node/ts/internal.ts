//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';

export class BridgedStringMap {
  readonly _nativeHandle: Native.BridgedStringMap;

  constructor(input: ReadonlyMap<string, string>) {
    this._nativeHandle = Native.BridgedStringMap_new(input.size);
    for (const [key, value] of input) {
      Native.BridgedStringMap_insert(this, key, value);
    }
  }

  dump(): string {
    return Native.TESTING_BridgedStringMap_dump_to_json(this);
  }
}

export function newNativeHandle<T>(handle: T): Native.Wrapper<T> {
  return {
    _nativeHandle: handle,
  };
}
