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

// From https://stackoverflow.com/a/46545530.
//
// Not as optimized as a Fisher-Yates-alike, but easy to convince yourself that it's correct.
export function shuffled<T>(input: T[]): T[] {
  return input
    .map((value) => ({ value, sort: Math.random() }))
    .sort((a, b) => a.sort - b.sort)
    .map(({ value }) => value);
}

// A utility class that allows its instance to act as both a promise and a handle used to fulfil the promise
export class CompletablePromise {
  promise: Promise<void>;
  resolve: (value: void | PromiseLike<void>) => void = () => {
    // no-op initial logic
  };

  constructor() {
    this.promise = new Promise<void>((resolve, _) => {
      this.resolve = resolve;
    });
  }

  public complete(): void {
    this.resolve();
  }

  public async done(): Promise<void> {
    await this.promise;
  }
}
