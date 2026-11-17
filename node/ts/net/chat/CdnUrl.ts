//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// The eslint importer doesn't like zod's namespaces. Typescript has no trouble,
// so it should be fine.
/* eslint-disable import/namespace */

import { Tagged } from 'type-fest';
import * as Native from '../../Native.js';
import * as z from 'zod/mini';

/**
 * A URL that points to a Signal CDN
 */
export type CdnUrl = Tagged<string, 'CdnUrl'>;
export namespace CdnUrl {
  export const Schema: z.ZodMiniType<CdnUrl, string> = z.pipe(
    z.string(),
    // We need to use Native (and not NativeNice) to avoid an import cycle
    z.custom<CdnUrl>((x: string) => Native.CdnUrl_validate(x))
  );

  export function isValid(input: string): input is CdnUrl {
    return Schema.safeParse(input).success;
  }

  export function fromString(input: string): CdnUrl {
    return Schema.parse(input);
  }
}
