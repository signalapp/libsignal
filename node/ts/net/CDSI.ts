//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import type { ReadonlyDeep } from 'type-fest';
import * as Native from '../Native.js';
import { Aci } from '../Address.js';
import { Buffer } from 'node:buffer';
import { TokioAsyncContext, ServiceAuth } from '../net.js';
import { newNativeHandle } from '../internal.js';

export type CDSRequestOptionsType = {
  e164s: Array<string>;
  acisAndAccessKeys: Array<{ aci: string; accessKey: string }>;
  abortSignal?: AbortSignal;
};

export type CDSResponseEntryType<Aci, Pni> = {
  aci: Aci | undefined;
  pni: Pni | undefined;
};

export type CDSResponseEntries<Aci, Pni> = Map<
  string,
  CDSResponseEntryType<Aci, Pni>
>;

export interface CDSResponseType<Aci, Pni> {
  entries: CDSResponseEntries<Aci, Pni>;
  debugPermitsUsed: number;
}

export async function cdsiLookup(
  {
    asyncContext,
    connectionManager,
  }: Readonly<{
    asyncContext: TokioAsyncContext;
    connectionManager: Native.Wrapper<Native.ConnectionManager>;
  }>,
  { username, password }: Readonly<ServiceAuth>,
  { e164s, acisAndAccessKeys, abortSignal }: ReadonlyDeep<CDSRequestOptionsType>
): Promise<CDSResponseType<string, string>> {
  const request = newNativeHandle(Native.LookupRequest_new());
  e164s.forEach((e164) => {
    Native.LookupRequest_addE164(request, e164);
  });

  acisAndAccessKeys.forEach(({ aci: aciStr, accessKey: accessKeyStr }) => {
    Native.LookupRequest_addAciAndAccessKey(
      request,
      Aci.parseFromServiceIdString(aciStr).getServiceIdFixedWidthBinary(),
      Buffer.from(accessKeyStr, 'base64')
    );
  });

  const lookup = await asyncContext.makeCancellable(
    abortSignal,
    Native.CdsiLookup_new(
      asyncContext,
      connectionManager,
      username,
      password,
      request
    )
  );
  return await asyncContext.makeCancellable(
    abortSignal,
    Native.CdsiLookup_complete(asyncContext, newNativeHandle(lookup))
  );
}
