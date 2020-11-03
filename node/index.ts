//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as SignalClient from './libsignal_client';
import bindings = require('bindings'); // eslint-disable-line import/order, @typescript-eslint/no-require-imports

// eslint-disable-next-line import/prefer-default-export
export const { PrivateKey } = bindings(
  'libsignal_client',
) as typeof SignalClient;
