//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import * as Native from './Native.js';

export function toJSONString(buffer: Bytes): string {
  return Native.MinidumpToJSONString(buffer);
}
