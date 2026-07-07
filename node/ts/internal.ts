//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from './Native.js';
import type { TokioAsyncContext } from './net.js';

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

/// Produces a `ReadableStream` from a bulk-pull stream implementation.
///
/// Not intended to be called outside of libsignal.
///
/// `ops.cancel` will be called when the ReadableStream is cancelled, which will also cancel any
/// active reads.
///
/// Note that unlike the other bridges, this doesn't handle transforming the stream's item type as
/// part of `wrapStream`, because that would often lead to cyclic dependencies with NativeNice.ts.
export function wrapStream<T, S>(
  asyncContext: TokioAsyncContext,
  handle: S,
  ops: {
    pull: (
      asyncContext: TokioAsyncContext,
      stream: S
    ) => Native.CancellablePromise<{
      chunk: Array<T>;
      termination: 'finished' | Error | null;
    }>;
    cancel: (stream: S) => void;
  }
): ReadableStream<T> {
  const abortController = new AbortController();
  let pendingError: Error | null = null;

  return new ReadableStream({
    pull: async (controller) => {
      if (pendingError) {
        throw pendingError;
      }

      const { chunk, termination } = await asyncContext.makeCancellable(
        abortController.signal,
        ops.pull(asyncContext, handle)
      );

      for (const next of chunk) {
        controller.enqueue(next);
      }

      if (termination !== null) {
        if (termination === 'finished') {
          controller.close();
        } else if (chunk.length === 0) {
          throw termination;
        } else {
          // Wait for a subsequent pull.
          pendingError = termination;
        }
      }
    },
    cancel: (reason) => {
      abortController.abort(reason);
      ops.cancel?.(handle);
    },
  });
}
