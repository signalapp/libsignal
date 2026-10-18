//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { Bytes } from '@signalapp/types';

import { ServiceId } from './Address.js';
import type { CdnCredentials } from './net/chat/CdnCredentials.js';
import * as Native from './Native.js';
import { newNativeHandle, wrapStream } from './internal.js';
import type { TokioAsyncContext } from './net.js';

export type DeviceId = number;
/**
 * The number of milliseconds since the epoch.
 */
export type Timestamp = number;

export function identity<T>(t: T): T {
  return t;
}

export function serviceIdArgConverter(account: ServiceId): Bytes {
  return account.getServiceIdFixedWidthBinary();
}

export function cdnCredentialReturnConverter(
  headers: [[string, string]]
): CdnCredentials {
  return {
    headers: new Map(headers),
  };
}

export function copyBackupMediaStreamConverter(
  streamHandle: Native.CopyBackupMediaStream
): (
  asyncContext: TokioAsyncContext
) => ReadableStream<Native.ReturnFfiBridgeCopyBackupMediaOutcome> {
  return (asyncContext) => {
    return wrapStream(asyncContext, newNativeHandle(streamHandle), {
      pull: Native.CopyBackupMediaStream_next,
      cancel: Native.CopyBackupMediaStream_cancel,
    });
  };
}

export function deleteBackupMediaStreamConverter(
  streamHandle: Native.DeleteBackupMediaStream
): (
  asyncContext: TokioAsyncContext
) => ReadableStream<Native.ReturnFfiBridgeDeleteBackupMediaItem> {
  return (asyncContext) => {
    return wrapStream(asyncContext, newNativeHandle(streamHandle), {
      pull: Native.DeleteBackupMediaStream_next,
      cancel: Native.DeleteBackupMediaStream_cancel,
    });
  };
}

export function grpcTestCaseConverter<ReqIn, ReqOut, RespIn, RespOut>(
  reqConverter: (x: ReqIn) => ReqOut,
  respConverter: (x: RespIn) => RespOut
): (
  x: Array<Native.GrpcTestCase<ReqIn, RespIn>>
) => Array<Native.GrpcTestCase<ReqOut, RespOut>> {
  return function (
    arr: Array<Native.GrpcTestCase<ReqIn, RespIn>>
  ): Array<Native.GrpcTestCase<ReqOut, RespOut>> {
    return arr.map((x) => {
      const { name, method, request, requestGrpc, responseGrpc, response } = x;
      return {
        name,
        method,
        request: reqConverter(request),
        requestGrpc,
        responseGrpc,
        response: respConverter(response),
      };
    });
  };
}

export function liftNull<In, Out>(
  f: (x: In) => Out
): (x: In | null) => Out | null {
  return function (x: In | null): Out | null {
    if (x === null) return null;
    return f(x);
  };
}

export function stringMapArgConverter<ValueFfi, ValueNice>(
  f: (x: ValueNice) => ValueFfi
): (map: Map<string, ValueNice>) => (string | ValueFfi)[] {
  return function (map: Map<string, ValueNice>): (string | ValueFfi)[] {
    const out: (string | ValueFfi)[] = [];
    for (const [k, v] of map.entries()) {
      out.push(k);
      out.push(f(v));
    }
    return out;
  };
}

export function stringMapResultConverter<ValueFfi, ValueNice>(
  f: (x: ValueFfi) => ValueNice
): (entries: (string | ValueFfi)[]) => Map<string, ValueNice> {
  return function (entries: (string | ValueFfi)[]): Map<string, ValueNice> {
    if (entries.length % 2 !== 0) {
      throw new RangeError('Expected an even-sized array');
    }
    const out: Map<string, ValueNice> = new Map();
    for (let i = 0; i < entries.length; i += 2) {
      out.set(entries[i] as string, f(entries[i + 1] as ValueFfi));
    }
    return out;
  };
}
