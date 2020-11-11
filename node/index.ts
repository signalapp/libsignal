//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import bindings = require('bindings'); // eslint-disable-line @typescript-eslint/no-require-imports
import * as SignalClient from './libsignal_client';

export const { PrivateKey } = bindings(
  'libsignal_client'
) as typeof SignalClient;
