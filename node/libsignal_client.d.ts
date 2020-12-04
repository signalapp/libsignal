//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint-disable import/prefer-default-export */

// FIXME: Eventually we should be able to autogenerate this.

// Newtype pattern from https://kubyshkin.name/posts/newtype-in-typescript/
interface PrivateKey {
  readonly __type: unique symbol;
}

export function PrivateKey_generate(): PrivateKey;
export function PrivateKey_serialize(key: PrivateKey): Buffer;
