//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint-disable import/prefer-default-export */

// FIXME: Eventually we should be able to autogenerate this.

// Newtype pattern from https://kubyshkin.name/posts/newtype-in-typescript/
interface PublicKey {
  readonly __type: unique symbol;
}

export function PublicKey_deserialize(buf: Buffer): PublicKey;
export function PublicKey_serialize(key: PublicKey): Buffer;
export function PublicKey_verify(
  key: PublicKey,
  msg: Buffer,
  signature: Buffer
): boolean;

interface PrivateKey {
  readonly __type: unique symbol;
}

export function PrivateKey_generate(): PrivateKey;
export function PrivateKey_deserialize(buf: Buffer): PrivateKey;
export function PrivateKey_serialize(key: PrivateKey): Buffer;
export function PrivateKey_sign(key: PrivateKey, msg: Buffer): Buffer;
export function PrivateKey_agree(key: PrivateKey, other_key: PublicKey): Buffer;
export function PrivateKey_getPublicKey(key: PrivateKey): PublicKey;
