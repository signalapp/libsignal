//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as SignalClient from './libsignal_client';
// 'bindings' is only supported as a CommonJS-style module.
// tslint:disable-next-line:no-require-imports
import bindings = require('bindings');
export const { PrivateKey } = bindings(
  'libsignal_client',
) as typeof SignalClient;
