//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as SignalClient from '../index';

export function initLogger(logLevel?: SignalClient.LogLevel): void {
  SignalClient.initLogger(
    logLevel ?? SignalClient.LogLevel.Trace,
    (_level, target, fileOrNull, lineOrNull, message) => {
      const targetPrefix = target ? `[${target}] ` : '';
      const file = fileOrNull ?? '<unknown>';
      const line = lineOrNull ?? 0;
      // eslint-disable-next-line no-console
      console.log(`${targetPrefix}${file}:${line}: ${message}`);
    }
  );
}
