//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';

export function toJSONString(buffer: Uint8Array): string {
  return Native.MinidumpToJSONString(buffer);
}
