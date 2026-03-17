//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as uuid from 'uuid';

export type Uuid = string;

export function parseUuid(input: string): Uint8Array<ArrayBuffer> {
  // @ts-expect-error See https://github.com/uuidjs/uuid/pull/927
  return uuid.parse(input);
}
