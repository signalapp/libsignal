//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { ServiceId } from './Address.js';

export function serviceIdArgConverter(
  account: ServiceId
): Uint8Array<ArrayBuffer> {
  return account.getServiceIdFixedWidthBinary();
}

export function identity<T>(t: T): T {
  return t;
}
