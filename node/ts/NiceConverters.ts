//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { ServiceId } from './Address.js';
import { type CdnCredentials } from './net/chat/CdnCredentials.js';
import * as Native from './Native.js';

export type DeviceId = number;
/**
 * The number of milliseconds since the epoch.
 */
export type Timestamp = number;

export function identity<T>(t: T): T {
  return t;
}

export function serviceIdArgConverter(
  account: ServiceId
): Uint8Array<ArrayBuffer> {
  return account.getServiceIdFixedWidthBinary();
}

export function cdnCredentialReturnConverter(
  headers: [[string, string]]
): CdnCredentials {
  return {
    headers: new Map(headers),
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
